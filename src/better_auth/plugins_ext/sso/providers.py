"""Provider CRUD, sanitization, org-admin access control, identity-boundary guard.

Faithful port of ``packages/sso/src/routes/providers.ts`` (OIDC only — the
SAML/spMetadataUrl/cert branch of ``sanitizeProvider`` and ``mergeSAMLConfig`` are
excluded). ``clientSecret`` is stored in the ``oidcConfig`` JSON in PLAINTEXT (a
cross-runtime DB-compat contract) and is masked only here, on every read path
(``sanitize_provider`` returns ``clientIdLastFour`` and omits the secret).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ...adapters.base import Where
from ...types import APIError, AuthResponse, Ctx
from .utils import mask_client_id, safe_json_parse

if TYPE_CHECKING:
    from . import SSOPlugin

ADMIN_ROLES = frozenset({"owner", "admin"})

OIDC_IDENTITY_BOUNDARY_FIELDS = (
    "authorizationEndpoint",
    "clientId",
    "discoveryEndpoint",
    "jwksEndpoint",
    "tokenEndpoint",
    "userInfoEndpoint",
)


# --- org-admin checks ----------------------------------------------------------------


def has_org_admin_role(role: str) -> bool:
    """Org-admin iff the comma-joined role string contains ``owner`` or ``admin``
    (providers.ts ``hasOrgAdminRole``)."""
    return any(part.strip() in ADMIN_ROLES for part in role.split(","))


async def is_org_admin(ctx: Ctx, user_id: str, organization_id: str) -> bool:
    member = await ctx.adapter.find_one(
        "member",
        [Where("userId", user_id), Where("organizationId", organization_id)],
    )
    return bool(member) and has_org_admin_role(member["role"])


async def batch_check_org_admin(ctx: Ctx, user_id: str, organization_ids: list[str]) -> set[str]:
    if not organization_ids:
        return set()
    members = await ctx.adapter.find_many(
        "member",
        [
            Where("userId", user_id),
            Where("organizationId", organization_ids, operator="in"),
        ],
    )
    return {m["organizationId"] for m in members if has_org_admin_role(m["role"])}


# --- sanitize ------------------------------------------------------------------------


def sanitize_provider(provider: dict[str, Any], base_url: str) -> dict[str, Any]:
    """OIDC-only sanitized view (providers.ts ``sanitizeProvider`` minus SAML): masks
    the client id (last four), never returns the client secret."""
    try:
        oidc = safe_json_parse(provider.get("oidcConfig"))
    except ValueError:
        oidc = None

    sanitized_oidc: dict[str, Any] | None = None
    if oidc:
        sanitized_oidc = {
            "discoveryEndpoint": oidc.get("discoveryEndpoint"),
            "clientIdLastFour": mask_client_id(oidc.get("clientId", "")),
            "pkce": oidc.get("pkce"),
            "authorizationEndpoint": oidc.get("authorizationEndpoint"),
            "tokenEndpoint": oidc.get("tokenEndpoint"),
            "userInfoEndpoint": oidc.get("userInfoEndpoint"),
            "jwksEndpoint": oidc.get("jwksEndpoint"),
            "scopes": oidc.get("scopes"),
            "tokenEndpointAuthentication": oidc.get("tokenEndpointAuthentication"),
        }

    return {
        "providerId": provider["providerId"],
        "type": "oidc",
        "issuer": provider["issuer"],
        "domain": provider["domain"],
        "organizationId": provider.get("organizationId") or None,
        "domainVerified": bool(provider.get("domainVerified")),
        "oidcConfig": sanitized_oidc,
    }


# --- access control ------------------------------------------------------------------


async def check_provider_access(
    plugin: SSOPlugin, ctx: Ctx, provider_id: str, user_id: str
) -> dict[str, Any]:
    provider = await ctx.adapter.find_one(plugin.model_name, [Where("providerId", provider_id)])
    if provider is None:
        raise APIError(404, "NOT_FOUND", "Provider not found")

    org_id = provider.get("organizationId")
    if org_id:
        if plugin.has_org_plugin(ctx):
            has_access = await is_org_admin(ctx, user_id, org_id)
        else:
            has_access = provider.get("userId") == user_id
    else:
        has_access = provider.get("userId") == user_id

    if not has_access:
        raise APIError(403, "FORBIDDEN", "You don't have access to this provider")
    return provider


# --- identity-boundary + merge -------------------------------------------------------


def _stable_stringify(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _identity_value_changed(current: Any, updated: Any) -> bool:
    return _stable_stringify(current) != _stable_stringify(updated)


def oidc_identity_boundary_changed(current: dict[str, Any], updated: dict[str, Any]) -> bool:
    if any(
        _identity_value_changed(current.get(f), updated.get(f))
        for f in OIDC_IDENTITY_BOUNDARY_FIELDS
    ):
        return True
    return _identity_value_changed(
        (current.get("mapping") or {}).get("id"),
        (updated.get("mapping") or {}).get("id"),
    )


def merge_oidc_config(
    current: dict[str, Any], updates: dict[str, Any], issuer: str
) -> dict[str, Any]:
    """Partial OIDC merge (providers.ts ``mergeOIDCConfig``): ``updates`` win, then
    explicit fallbacks; ``issuer`` overrides; ``pkce`` defaults to True."""

    def pick(field: str) -> Any:
        value = updates.get(field)
        return value if value is not None else current.get(field)

    merged = {**current, **updates, "issuer": issuer}
    merged["pkce"] = (
        updates.get("pkce")
        if updates.get("pkce") is not None
        else (current.get("pkce") if current.get("pkce") is not None else True)
    )
    for field in (
        "clientId",
        "clientSecret",
        "discoveryEndpoint",
        "mapping",
        "scopes",
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInfoEndpoint",
        "jwksEndpoint",
        "tokenEndpointAuthentication",
    ):
        merged[field] = pick(field)
    return merged


# --- endpoint handlers ---------------------------------------------------------------


async def list_providers(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    user_id = session["user"]["id"]

    all_providers = await ctx.adapter.find_many(plugin.model_name)
    owned = [p for p in all_providers if p.get("userId") == user_id and not p.get("organizationId")]
    org_providers = [p for p in all_providers if p.get("organizationId")]

    accessible = list(owned)
    if plugin.has_org_plugin(ctx) and org_providers:
        org_ids = list({p["organizationId"] for p in org_providers})
        admin_ids = await batch_check_org_admin(ctx, user_id, org_ids)
        accessible.extend(p for p in org_providers if p["organizationId"] in admin_ids)
    elif not plugin.has_org_plugin(ctx):
        accessible.extend(p for p in org_providers if p.get("userId") == user_id)

    base_url = plugin.context_base_url(ctx)
    return AuthResponse(body={"providers": [sanitize_provider(p, base_url) for p in accessible]})


async def get_provider(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    provider_id = ctx.request.query.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    provider = await check_provider_access(plugin, ctx, provider_id, session["user"]["id"])
    return AuthResponse(body=sanitize_provider(provider, plugin.context_base_url(ctx)))


async def update_provider(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    from .discovery import (
        DiscoveryError,
        map_discovery_error_to_api_error,
        validate_skip_discovery_endpoints,
    )

    session = await ctx.require_session()
    user_id = session["user"]["id"]
    body = ctx.body()
    provider_id = body.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")

    issuer = body.get("issuer")
    domain = body.get("domain")
    oidc_config = body.get("oidcConfig")
    if not issuer and not domain and not oidc_config:
        raise APIError(400, "BAD_REQUEST", "No fields provided for update")

    existing = await check_provider_access(plugin, ctx, provider_id, user_id)

    update_data: dict[str, Any] = {}
    identity_changed = issuer is not None and issuer != existing["issuer"]

    if issuer is not None:
        update_data["issuer"] = issuer
    if domain is not None:
        update_data["domain"] = domain
        if domain != existing["domain"]:
            update_data["domainVerified"] = False

    if oidc_config:
        try:
            validate_skip_discovery_endpoints(oidc_config, ctx.auth.is_trusted_url)
        except DiscoveryError as error:
            raise map_discovery_error_to_api_error(error) from error

        try:
            current = safe_json_parse(existing.get("oidcConfig"))
        except ValueError:
            current = None
        if not current:
            raise APIError(
                400,
                "BAD_REQUEST",
                "Cannot update OIDC config for a provider that doesn't have OIDC configured",
            )
        updated = merge_oidc_config(
            current,
            oidc_config,
            update_data.get("issuer") or current.get("issuer") or existing["issuer"],
        )
        if oidc_identity_boundary_changed(current, updated):
            identity_changed = True
        update_data["oidcConfig"] = json.dumps(updated, separators=(",", ":"), ensure_ascii=False)

    if identity_changed:
        linked = await ctx.adapter.find_one("account", [Where("providerId", provider_id)])
        if linked:
            raise APIError(
                409,
                "CONFLICT",
                "Cannot change SSO provider identity fields while linked accounts exist",
            )

    await ctx.adapter.update(plugin.model_name, [Where("providerId", provider_id)], update_data)
    full = await ctx.adapter.find_one(plugin.model_name, [Where("providerId", provider_id)])
    if full is None:
        raise APIError(404, "NOT_FOUND", "Provider not found after update")
    return AuthResponse(body=sanitize_provider(full, plugin.context_base_url(ctx)))


async def delete_provider(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    body = ctx.body()
    provider_id = body.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    await check_provider_access(plugin, ctx, provider_id, session["user"]["id"])

    model_name = plugin.model_name

    async def _tx(tx: Any) -> None:
        await tx.delete_many("account", [Where("providerId", provider_id)])
        await tx.delete_many(model_name, [Where("providerId", provider_id)])

    await ctx.adapter.transaction(_tx)
    return AuthResponse(body={"success": True})
