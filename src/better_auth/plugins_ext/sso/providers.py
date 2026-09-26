"""Provider CRUD, sanitization, org-admin access control, identity-boundary guard.

Faithful port of ``packages/sso/src/routes/providers.ts`` (OIDC only — the
SAML/spMetadataUrl/cert branch of ``sanitizeProvider`` and ``mergeSAMLConfig`` are
excluded). ``clientSecret`` is stored in the ``oidcConfig`` JSON in PLAINTEXT (a
cross-runtime DB-compat contract) and is masked only here, on every read path
(``sanitize_provider`` returns ``clientIdLastFour`` and omits the secret).
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import TYPE_CHECKING, Any

from ...adapters.base import BaseAdapter, Where
from ...types import APIError, AuthResponse, Ctx
from .provider_reference import compute_sso_provider_reference
from .utils import mask_client_id, safe_json_parse

if TYPE_CHECKING:
    from . import SSOPlugin

logger = logging.getLogger("better_auth")

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


def _returned_additional_fields(plugin: SSOPlugin, provider: dict[str, Any]) -> dict[str, Any]:
    """Configured ``additionalFields`` present on the row, minus ``returned: false``
    (TS v1.7.6 providers.ts:392-408)."""
    return {
        key: provider[key]
        for key, spec in plugin.additional_fields.items()
        if spec.returned and key in provider
    }


def sanitize_provider(plugin: SSOPlugin, provider: dict[str, Any], base_url: str) -> dict[str, Any]:
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
        **_returned_additional_fields(plugin, provider),
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


# --- identity boundary, row lock, mutation guard -------------------------------------


def _boundary_value(config: dict[str, Any] | None, field: str) -> str:
    """TS ``stableStringify`` of one field; an absent key reads as ``undefined``."""
    if not config or field not in config:
        return "undefined"
    return json.dumps(config[field], sort_keys=True, separators=(",", ":"))


def oidc_identity_boundary_changed(current: dict[str, Any], updated: dict[str, Any]) -> bool:
    return any(
        _boundary_value(current, f) != _boundary_value(updated, f)
        for f in OIDC_IDENTITY_BOUNDARY_FIELDS
    )


def _config_snapshot(config: Any, config_type: str) -> dict[str, Any] | None:
    if not config:
        return None
    if isinstance(config, dict):
        return config
    return parse_and_validate_config(config, config_type)


def parse_and_validate_config(value: Any, config_type: str) -> dict[str, Any]:
    try:
        config = safe_json_parse(value)
    except ValueError:
        config = None
    if not config:
        raise APIError(
            400,
            "BAD_REQUEST",
            f"Cannot update {config_type} config for a provider that doesn't have "
            f"{config_type} configured",
        )
    return config


def sso_provider_identity_boundary_changed(
    current: dict[str, Any], updated: dict[str, Any]
) -> bool:
    """TS v1.7.6 providers.ts:204-246 ``ssoProviderIdentityBoundaryChanged``."""
    if current.get("issuer") != updated.get("issuer"):
        return True
    current_saml = _config_snapshot(current.get("samlConfig"), "SAML")
    if current_saml:
        updated_saml = _config_snapshot(updated.get("samlConfig"), "SAML")
        # ponytail: SAML is not ported, so any SAML config change counts as a boundary
        # change (TS compares the derived IdP/SP identity). Port samlIdentityBoundaryChanged
        # with SAML.
        if updated_saml != current_saml:
            return True
    current_oidc = _config_snapshot(current.get("oidcConfig"), "OIDC")
    if not current_oidc:
        return False
    updated_oidc = _config_snapshot(updated.get("oidcConfig"), "OIDC")
    return not updated_oidc or oidc_identity_boundary_changed(current_oidc, updated_oidc)


async def lock_sso_provider_row(
    plugin: SSOPlugin, adapter: Any, provider_id: str, row_id: str | None
) -> dict[str, Any] | None:
    """TS v1.7.6 providers.ts:248-262: a no-op write takes the row lock inside the
    transaction and returns the current row (None when it is gone)."""
    where = ([Where("id", row_id)] if row_id else []) + [Where("providerId", provider_id)]
    return await adapter.update(plugin.model_name, where, {"providerId": provider_id})


async def lock_sso_provider_for_account_link(
    plugin: SSOPlugin, adapter: Any, provider: dict[str, Any]
) -> None:
    """TS v1.7.6 providers.ts:334-359: a persisted provider is locked for the account
    link and refused when it vanished or its identity boundary moved."""
    if not isinstance(provider.get("id"), str):
        return
    changed = APIError(
        409, "SSO_PROVIDER_CHANGED", "SSO provider changed while account linking was in progress"
    )
    locked = await lock_sso_provider_row(plugin, adapter, provider["providerId"], provider["id"])
    if locked is None or sso_provider_identity_boundary_changed(provider, locked):
        raise changed


async def _guard_provider_mutation(
    plugin: SSOPlugin, mutation: dict[str, Any], provider: dict[str, Any], database: Any
) -> None:
    """TS v1.7.6 providers.ts:264-310: the application guard runs on the locked row;
    any failure becomes a stable 409."""
    if plugin.guard_provider_mutation is None:
        return
    reference = compute_sso_provider_reference(
        {
            **provider,
            "organizationId": provider.get("organizationId"),
            "oidcConfig": _config_snapshot(provider.get("oidcConfig"), "OIDC"),
            "samlConfig": _config_snapshot(provider.get("samlConfig"), "SAML"),
        }
    )
    data = {
        **mutation,
        "provider": {
            "id": provider.get("id"),
            "providerId": provider["providerId"],
            "organizationId": provider.get("organizationId"),
        },
        "providerReference": reference,
    }
    try:
        result = plugin.guard_provider_mutation(data, {"database": database})
        if inspect.isawaitable(result):
            await result
    except Exception:
        logger.error("SSO provider mutation guard rejected the mutation")
        raise APIError(
            409, "SSO_PROVIDER_MUTATION_REJECTED", "SSO provider mutation is not allowed"
        ) from None


def _assert_guard_capabilities(plugin: SSOPlugin, ctx: Ctx) -> None:
    if plugin.guard_provider_mutation is None:
        return
    if type(ctx.adapter).transaction is BaseAdapter.transaction:
        raise APIError(
            501,
            "SSO_PROVIDER_MUTATION_GUARD_REQUIRES_NATIVE_TRANSACTIONS",
            "SSO provider mutation guards require a database adapter with native "
            "transaction support",
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
        "privateKeyId",
        "privateKeyAlgorithm",
    ):
        merged[field] = pick(field)
    return {key: value for key, value in merged.items() if value is not None}


def assert_token_endpoint_auth_config(
    plugin: SSOPlugin, config: dict[str, Any], provider_id: str
) -> None:
    """TS v1.7.6 sso.ts:672-700 / providers.ts:960-989: a secret method needs the
    secret; ``private_key_jwt`` needs a key source outside the database."""
    method = config.get("tokenEndpointAuthentication")
    if method != "private_key_jwt" and not config.get("clientSecret"):
        raise APIError(
            400,
            "BAD_REQUEST",
            "clientSecret is required when using client_secret_basic or client_secret_post "
            "authentication",
        )
    if (
        method == "private_key_jwt"
        and plugin.resolve_private_key is None
        and not any(
            p.get("providerId") == provider_id and p.get("privateKey") for p in plugin.default_sso
        )
    ):
        raise APIError(
            400,
            "BAD_REQUEST",
            "private_key_jwt authentication requires either a resolvePrivateKey callback or a "
            "privateKey in defaultSSO",
        )


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
    return AuthResponse(
        body={"providers": [sanitize_provider(plugin, p, base_url) for p in accessible]}
    )


async def get_provider(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    provider_id = ctx.request.query.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    provider = await check_provider_access(plugin, ctx, provider_id, session["user"]["id"])
    return AuthResponse(body=sanitize_provider(plugin, provider, plugin.context_base_url(ctx)))


async def update_provider(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    """TS v1.7.6 providers.ts:810-1060: validated, then applied inside a transaction that
    locks the row and re-reads it, so the identity-boundary and linked-account checks see
    the locked state."""
    from .discovery import (
        DiscoveryError,
        map_discovery_error_to_api_error,
        validate_oidc_endpoint_urls,
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
    additional = plugin.parse_additional_fields(
        {k: v for k, v in body.items() if k != "providerId"}, "update"
    )
    if not issuer and not domain and not oidc_config and not additional:
        raise APIError(400, "BAD_REQUEST", "No fields provided for update")

    authorized = await check_provider_access(plugin, ctx, provider_id, user_id)
    _assert_guard_capabilities(plugin, ctx)
    model_name = plugin.model_name

    async def apply(tx: Any) -> dict[str, Any]:
        existing = await lock_sso_provider_row(plugin, tx.adapter, provider_id, authorized["id"])
        if existing is None:
            raise APIError(404, "NOT_FOUND", "Provider not found")
        update_data: dict[str, Any] = dict(additional)
        identity_changed = issuer is not None and issuer != existing["issuer"]
        if issuer is not None:
            update_data["issuer"] = issuer
        if domain is not None:
            update_data["domain"] = domain
            # the column exists only with domain verification on (TS's adapters drop
            # fields outside the schema)
            if domain != existing["domain"] and plugin.domain_verification_enabled:
                update_data["domainVerified"] = False

        if oidc_config:
            try:
                validate_oidc_endpoint_urls(oidc_config, ctx.auth.is_trusted_url)
            except DiscoveryError as error:
                raise map_discovery_error_to_api_error(error) from error
            current = parse_and_validate_config(existing.get("oidcConfig"), "OIDC")
            updated = merge_oidc_config(
                current,
                oidc_config,
                update_data.get("issuer") or current.get("issuer") or existing["issuer"],
            )
            assert_token_endpoint_auth_config(plugin, updated, provider_id)
            if oidc_identity_boundary_changed(current, updated):
                identity_changed = True
            update_data["oidcConfig"] = json.dumps(
                updated, separators=(",", ":"), ensure_ascii=False
            )

        await _guard_provider_mutation(
            plugin,
            {"action": "update", "isAuthenticationBoundaryChange": identity_changed},
            existing,
            tx.adapter,
        )
        if identity_changed:
            linked = await tx.adapter.find_one("account", [Where("providerId", provider_id)])
            if linked:
                raise APIError(
                    409,
                    "CONFLICT",
                    "Cannot change SSO provider identity fields while linked accounts exist",
                )

        await tx.adapter.update(model_name, [Where("providerId", provider_id)], update_data)
        full = await tx.adapter.find_one(model_name, [Where("providerId", provider_id)])
        if full is None:
            raise APIError(404, "NOT_FOUND", "Provider not found after update")
        return full

    full = await ctx.internal.transaction(apply)
    return AuthResponse(body=sanitize_provider(plugin, full, plugin.context_base_url(ctx)))


async def delete_provider(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    """TS v1.7.6 providers.ts:1063-1137: lock, guard, then delete the linked accounts and
    the exact locked row in one transaction."""
    session = await ctx.require_session()
    body = ctx.body()
    provider_id = body.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    authorized = await check_provider_access(plugin, ctx, provider_id, session["user"]["id"])
    _assert_guard_capabilities(plugin, ctx)

    model_name = plugin.model_name

    async def _tx(tx: Any) -> None:
        existing = await lock_sso_provider_row(plugin, tx.adapter, provider_id, authorized["id"])
        if existing is None:
            raise APIError(404, "NOT_FOUND", "Provider not found")
        await _guard_provider_mutation(plugin, {"action": "delete"}, existing, tx.adapter)
        await tx.adapter.delete_many("account", [Where("providerId", provider_id)])
        await tx.adapter.delete(
            model_name, [Where("id", existing["id"]), Where("providerId", provider_id)]
        )

    await ctx.internal.transaction(_tx)
    return AuthResponse(body={"success": True})
