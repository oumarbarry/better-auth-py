"""OAuth protected resources: the ``oauthResource`` model, its token policy, and seeding.

Port of TS ``packages/oauth-provider/src/resources.ts`` (v1.7.6, d2a79bae7 + 2fd3d5850 +
aedcb974f). A requested RFC 8707 ``resource`` must name an enabled ``oauthResource`` row (and,
with ``enforce_per_client_resources``, one linked to the client through
``oauthClientResource``); the row's policy narrows scopes, caps token lifetimes, pins the
signing key, adds custom claims, and may require DPoP. A token ``aud`` value stays valid while
its row exists, so deleting a row revokes the tokens bound to it.
"""

from __future__ import annotations

import inspect
import logging
import re
import weakref
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ...adapters.base import Where
from ...session import utcnow
from ...types import Ctx
from .utils import OAuthError

logger = logging.getLogger("better_auth")

#: TS ``JWS_ALGORITHMS`` (resources.ts:23), the jwt plugin's asymmetric algorithms.
JWS_ALGORITHMS = ("EdDSA", "ES256", "ES512", "PS256", "RS256")

#: TS ``MAX_AUD_VALUES`` (resources.ts:58).
MAX_AUD_VALUES = 64

#: TS ``MISSING_TABLE_PATTERN`` (resources.ts:814).
_MISSING_TABLE = re.compile(
    r"no such table|relation.*does not exist|table.*does(?: not|n[''']?t) exist", re.IGNORECASE
)
_UNIQUE_VIOLATION = re.compile(r"unique|duplicate", re.IGNORECASE)


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _base_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}"


def user_info_resource(ctx: Ctx) -> str:
    """The implicit OIDC UserInfo audience (resources.ts:213)."""
    return f"{_base_url(ctx)}/oauth2/userinfo"


def _legacy_audiences(opts: Any) -> set[str]:
    """Port-only: identifiers from the 1.0 ``valid_audiences`` option, accepted as resources
    with no policy and no client linkage. TS 1.7 dropped ``validAudiences``; the option is
    unset by default so the default path follows TS exactly."""
    return set(getattr(opts, "valid_audiences", None) or [])


# --- identifier validation (resources.ts:81) ------------------------------------------


def _is_absolute_uri(value: str) -> bool:
    """WHATWG ``new URL(value)`` succeeds: a scheme followed by ``:``."""
    parts = urlsplit(value)
    return bool(parts.scheme) and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value) is not None


async def check_identifier(opts: Any, identifier: Any) -> str | None:
    """The reason ``identifier`` fails RFC 8707 §2 validation, or ``None`` when it passes, TS
    ``checkIdentifier``. A configured ``identifier_validator`` replaces the default rule."""
    validator = getattr(opts, "identifier_validator", None)
    if validator is not None:
        if not await _await(validator(identifier)):
            return f"resource identifier {identifier} failed validation"
        return None
    if not isinstance(identifier, str) or not _is_absolute_uri(identifier):
        return f"resource identifier {identifier} must be an absolute URI (RFC 8707 §2)"
    if urlsplit(identifier).fragment:
        return f"resource identifier {identifier} must not contain a URI fragment (RFC 8707 §2)"
    return None


async def assert_identifier_valid(opts: Any, identifier: str) -> None:
    """TS ``assertIdentifierValid``: ``invalid_target`` when the identifier is rejected."""
    reason = await check_identifier(opts, identifier)
    if reason:
        raise OAuthError(400, "invalid_target", reason)


def resource_uri_issue(value: Any) -> str | None:
    """TS ``ResourceUriSchema`` (types/zod.ts:23): absolute URI, no fragment, no dangerous
    scheme. Returns the issue message or ``None``."""
    if not isinstance(value, str) or not _is_absolute_uri(value):
        return "resource must be an absolute URI"
    if "#" in value:
        return "resource must not contain a fragment"
    if urlsplit(value).scheme.lower() in ("javascript", "data", "vbscript"):
        return "resource cannot use javascript:, data:, or vbscript: scheme"
    return None


# --- parameter helpers ---------------------------------------------------------------


def to_resource_list(value: Any) -> list[str] | None:
    """TS ``toResourceList`` (utils/index.ts:190): a non-empty list or ``None``."""
    if isinstance(value, str):
        return [value]
    if not value:
        return None
    return list(value)


def to_audience_claim(audience: Any) -> Any:
    """TS ``toAudienceClaim`` (utils/index.ts:201): a lone value collapses to a string."""
    if isinstance(audience, str):
        return audience
    if not audience:
        return None
    return audience[0] if len(audience) == 1 else list(audience)


def normalize_resource_param(resource: Any) -> list[str] | None:
    """TS ``normalizeResourceParam`` (resources.ts:262)."""
    if resource is None:
        return None
    if isinstance(resource, str):
        return [resource]
    if isinstance(resource, (list, tuple)):
        values = [r for r in resource if isinstance(r, str) and r]
        return values or None
    return None


def extract_repeated_resource_from_form(ctx: Ctx) -> list[str] | None:
    """Every non-empty ``resource`` value of a form body, TS
    ``extractRepeatedResourceFromForm`` (resources.ts:237)."""
    ctype = (ctx.request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" not in ctype or not ctx.request.body:
        return None
    pairs = parse_qsl(ctx.request.body.decode("utf-8", "replace"), keep_blank_values=True)
    values = [v for k, v in pairs if k == "resource" and v]
    return values or None


# --- lookup + cache (resources.ts:660-711) -------------------------------------------

#: TS module-scoped ``resourceCache``, keyed by identifier (opt-in via ``cached_resources``).
_resource_cache: dict[str, dict[str, Any]] = {}


def invalidate_resource_cache(identifier: str | None = None) -> None:
    """TS ``invalidateResourceCache``: drop one entry, or everything when ``None``."""
    if identifier is None:
        _resource_cache.clear()
    else:
        _resource_cache.pop(identifier, None)


async def get_resource(ctx: Ctx, opts: Any, identifier: str) -> dict[str, Any] | None:
    """TS ``getResource``: lazy-seed, then the cache (members of ``cached_resources`` only),
    then the database. Returns a copy."""
    await seed_resources_once(ctx, opts)
    cached_ids = getattr(opts, "cached_resources", None) or set()
    if identifier in cached_ids and identifier in _resource_cache:
        return dict(_resource_cache[identifier])
    row = await ctx.adapter.find_one("oauthResource", [Where("identifier", identifier)])
    if row and identifier in cached_ids:
        _resource_cache[identifier] = dict(row)
    return row


async def is_audience_claim_allowed(
    ctx: Ctx, opts: Any, audience_claim: Any, implicit_audiences: Any = ()
) -> bool:
    """Every non-implicit ``aud`` value must resolve to an ``oauthResource`` row, TS
    ``isAudienceClaimAllowed`` (resources.ts:283). Disabled rows still pass."""
    if audience_claim is None:
        return True
    values = audience_claim if isinstance(audience_claim, list) else [audience_claim]
    if len(values) > MAX_AUD_VALUES:
        return False
    implicit = set(implicit_audiences) | _legacy_audiences(opts)
    lookup = list(dict.fromkeys(v for v in values if v not in implicit))
    for identifier in lookup:
        if not isinstance(identifier, str) or not await get_resource(ctx, opts, identifier):
            return False
    return True


# --- policy resolution (resources.ts:336) --------------------------------------------


def _enforce_per_client(opts: Any) -> bool:
    """TS ``resolveEnforcePerClientResources``: explicit value, otherwise ``True``."""
    value = getattr(opts, "enforce_per_client_resources", None)
    return True if value is None else bool(value)


def log_enforce_per_client_resources_resolution(opts: Any) -> None:
    """TS ``logEnforcePerClientResourcesResolution`` (resources.ts:1016)."""
    explicit = getattr(opts, "enforce_per_client_resources", None) is not None
    logger.info(
        "oauth-provider: enforcePerClientResources resolved to %s (%s)",
        "true" if _enforce_per_client(opts) else "false",
        "explicit" if explicit else "default",
    )


def empty_policy(requested_scopes: list[str]) -> dict[str, Any]:
    return {
        "audienceClaim": None,
        "accessTokenTtl": None,
        "refreshTokenTtl": None,
        "signingAlgorithm": None,
        "signingKeyId": None,
        "rawCustomClaims": {},
        "dpopBoundAccessTokensRequired": False,
        "effectiveScopes": list(requested_scopes),
    }


async def resolve_resource_policy(
    ctx: Ctx, opts: Any, *, resource: Any, client_id: str, requested_scopes: list[str]
) -> dict[str, Any]:
    """TS ``resolveResourcePolicy``: validate the requested resources and merge their policy.
    Raises ``invalid_target`` (unknown, disabled, unlinked), ``invalid_scope`` (an allowlist
    excludes every requested scope) or ``invalid_request`` (conflicting signing pins)."""
    requested = normalize_resource_param(resource)
    if not requested:
        return empty_policy(requested_scopes)

    unique = list(dict.fromkeys(requested))
    userinfo = user_info_resource(ctx)
    legacy = _legacy_audiences(opts)
    resolved: list[dict[str, Any]] = []
    for identifier in unique:
        if identifier == userinfo or identifier in legacy:
            continue
        row = await get_resource(ctx, opts, identifier)
        if row is None:
            raise OAuthError(
                400, "invalid_target", f"requested resource {identifier} is not configured"
            )
        if row.get("disabled"):
            raise OAuthError(400, "invalid_target", f"requested resource {identifier} is disabled")
        resolved.append(row)

    if _enforce_per_client(opts) and resolved:
        await _assert_client_linked_to_resources(ctx, client_id, resolved)

    effective = list(requested_scopes)
    for row in resolved:
        allowed = row.get("allowedScopes")
        if allowed is None:
            continue
        allowed_set = set(allowed)
        intersection = [s for s in effective if s in allowed_set]
        if not intersection:
            raise OAuthError(
                400,
                "invalid_scope",
                f"none of the requested scopes are allowed for resource {row['identifier']}",
            )
        effective = intersection

    access_ttl: int | None = None
    refresh_ttl: int | None = None
    for row in resolved:
        if row.get("accessTokenTtl") is not None:
            ttl = row["accessTokenTtl"]
            access_ttl = ttl if access_ttl is None else min(access_ttl, ttl)
        if row.get("refreshTokenTtl") is not None:
            ttl = row["refreshTokenTtl"]
            refresh_ttl = ttl if refresh_ttl is None else min(refresh_ttl, ttl)

    algs = list(dict.fromkeys(r["signingAlgorithm"] for r in resolved if r.get("signingAlgorithm")))
    kids = list(dict.fromkeys(r["signingKeyId"] for r in resolved if r.get("signingKeyId")))
    if len(algs) > 1:
        raise OAuthError(
            400,
            "invalid_request",
            "multi-resource request has conflicting signingAlgorithm pins; a single JWS "
            "signature cannot satisfy multiple algorithms",
        )
    if len(kids) > 1:
        raise OAuthError(
            400,
            "invalid_request",
            "multi-resource request has conflicting signingKeyId pins; a single JWS "
            "signature cannot satisfy multiple key ids",
        )

    merged: dict[str, Any] = {}
    for row in resolved:
        if isinstance(row.get("customClaims"), dict):
            merged.update(row["customClaims"])

    audience = [*unique, userinfo] if "openid" in requested_scopes else unique
    audience = list(dict.fromkeys(audience))
    return {
        "audienceClaim": audience[0] if len(audience) == 1 else audience,
        "accessTokenTtl": access_ttl,
        "refreshTokenTtl": refresh_ttl,
        "signingAlgorithm": algs[0] if algs else None,
        "signingKeyId": kids[0] if kids else None,
        "rawCustomClaims": merged,
        "dpopBoundAccessTokensRequired": any(
            r.get("dpopBoundAccessTokensRequired") is True for r in resolved
        ),
        "effectiveScopes": effective,
    }


async def _assert_client_linked_to_resources(
    ctx: Ctx, client_id: str, resources: list[dict[str, Any]]
) -> None:
    """TS ``assertClientLinkedToResources`` (resources.ts:530)."""
    links = await ctx.adapter.find_many("oauthClientResource", [Where("clientId", client_id)])
    linked = {link.get("resourceId") for link in links or []}
    unlinked = [r["identifier"] for r in resources if r["identifier"] not in linked]
    if unlinked:
        raise OAuthError(
            400,
            "invalid_target",
            f"client {client_id} is not linked to resource(s) {', '.join(unlinked)}",
        )


async def is_client_linked_to_any_resource(
    ctx: Ctx, client_id: str, resource_identifiers: list[str]
) -> bool:
    """TS ``isClientLinkedToAnyResource`` (resources.ts:565): authorizes a resource server to
    introspect a token issued to another client."""
    if not resource_identifiers:
        return False
    links = await ctx.adapter.find_many(
        "oauthClientResource",
        [
            Where("clientId", client_id),
            Where("resourceId", list(resource_identifiers), operator="in"),
        ],
        limit=1,
    )
    return bool(links)


async def get_resource_custom_claims(ctx: Ctx, resource_identifiers: list[str]) -> dict[str, Any]:
    """TS ``getResourceCustomClaims`` (resources.ts:597): merged ``customClaims`` of the rows
    that still exist, in the token's resource order, with no issuance gates."""
    if not resource_identifiers:
        return {}
    rows = await ctx.adapter.find_many(
        "oauthResource", [Where("identifier", list(resource_identifiers), operator="in")]
    )
    by_id = {row["identifier"]: row for row in rows}
    merged: dict[str, Any] = {}
    for identifier in resource_identifiers:
        claims = (by_id.get(identifier) or {}).get("customClaims")
        if isinstance(claims, dict):
            merged.update(claims)
    return merged


# --- seeding (resources.ts:727-1006) -------------------------------------------------


def collect_resource_inputs(opts: Any) -> list[dict[str, Any]]:
    """TS ``collectResourceInputs``: string entries become ``{identifier}``."""
    return [
        {"identifier": entry} if isinstance(entry, str) else dict(entry)
        for entry in (getattr(opts, "resources", None) or [])
    ]


_POLICY_FIELDS = (
    "accessTokenTtl",
    "refreshTokenTtl",
    "signingAlgorithm",
    "signingKeyId",
    "allowedScopes",
    "customClaims",
)


def _seed_row(entry: dict[str, Any], now: datetime) -> dict[str, Any]:
    """TS ``buildSeedRow``."""
    return {
        "identifier": entry["identifier"],
        "name": entry.get("name") if entry.get("name") is not None else entry["identifier"],
        **{field: entry.get(field) for field in _POLICY_FIELDS},
        "dpopBoundAccessTokensRequired": entry.get("dpopBoundAccessTokensRequired") or False,
        "disabled": entry.get("disabled") or False,
        "policyVersion": 1,
        "metadata": entry.get("metadata"),
        "createdAt": now,
        "updatedAt": now,
    }


def _seed_update(entry: dict[str, Any], mode: str, now: datetime) -> dict[str, Any]:
    """TS ``buildSeedUpdate``: ``overwrite`` replaces every policy column, ``merge`` only
    writes the fields present in the config entry."""
    if mode == "overwrite":
        row = _seed_row(entry, now)
        row.pop("identifier")
        row.pop("createdAt")
        return row
    update: dict[str, Any] = {"updatedAt": now}
    for field in (
        "name",
        *_POLICY_FIELDS,
        "dpopBoundAccessTokensRequired",
        "disabled",
        "metadata",
    ):
        if field in entry:
            update[field] = entry[field]
    return update


async def seed_resources(ctx: Ctx, opts: Any) -> bool:
    """TS ``seedResources``: insert (and per ``resource_seed_mode`` update) the configured
    resources. Returns ``False`` when the table does not exist yet (seed deferred)."""
    mode = getattr(opts, "resource_seed_mode", None) or "insertOnly"
    for raw in collect_resource_inputs(opts):
        reason = await check_identifier(opts, raw.get("identifier"))
        if reason:
            logger.warning(
                "oauth-provider: skipping resource seed for %s: %s", raw.get("identifier"), reason
            )
            continue
        entry = raw
        alg = entry.get("signingAlgorithm")
        if alg is not None and alg not in JWS_ALGORITHMS:
            logger.warning(
                'oauth-provider: dropping unsupported signingAlgorithm "%s" for resource %s: '
                "must be one of %s. Continuing without an algorithm override.",
                alg,
                entry["identifier"],
                ", ".join(JWS_ALGORITHMS),
            )
            entry = {k: v for k, v in entry.items() if k != "signingAlgorithm"}
        try:
            existing = await ctx.adapter.find_one(
                "oauthResource", [Where("identifier", entry["identifier"])]
            )
        except Exception as exc:
            if _MISSING_TABLE.search(str(exc)):
                return False
            raise
        now = datetime.fromtimestamp(utcnow().timestamp(), tz=timezone.utc)
        if not existing:
            try:
                await ctx.adapter.create("oauthResource", _seed_row(entry, now))
            except Exception as exc:
                if _UNIQUE_VIOLATION.search(str(exc)):
                    continue
                if _MISSING_TABLE.search(str(exc)):
                    return False
                raise
            continue
        if mode == "insertOnly":
            continue
        await ctx.adapter.update(
            "oauthResource",
            [Where("identifier", entry["identifier"])],
            _seed_update(entry, mode, now),
        )
    return True


#: Per-adapter "seed completed" flags (TS ``seedStates``, keyed by adapter).
_seeded: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


async def seed_resources_once(ctx: Ctx, opts: Any) -> None:
    """TS ``seedResourcesOnce``: seed on first resource access, once per adapter.

    ponytail: the Python plugin ``init`` is synchronous, so the TS init-time seed runs here on
    the first resource lookup instead. Concurrent first requests may both seed; the unique
    identifier and the ``insertOnly`` default make that harmless. Add an async startup hook
    to the plugin contract to seed eagerly."""
    adapter = ctx.adapter
    if _seeded.get(adapter):
        return
    if not getattr(opts, "resources", None):
        _seeded[adapter] = True
        return
    if await seed_resources(ctx, opts):
        _seeded[adapter] = True


def reset_seed_state_for_tests() -> None:
    """TS ``resetSeedStateForTests``."""
    global _seeded
    _seeded = weakref.WeakKeyDictionary()
