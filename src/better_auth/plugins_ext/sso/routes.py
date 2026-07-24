"""``POST /sso/register`` — register an OIDC provider (Wave B).

Port of ``registerSSOProvider`` (``packages/sso/src/routes/sso.ts``), OIDC path only.
The SAML config branch is excluded: a ``providerType:"saml"`` (or a ``samlConfig``
body) is rejected with a BAD_REQUEST rather than silently branched. ``buildOIDCConfig``
serializes the exact cross-runtime JSON blob (``clientSecret`` in plaintext; keys with
absent values dropped, mirroring ``JSON.stringify`` omitting ``undefined``).
"""

from __future__ import annotations

import inspect
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ...adapters.base import Where
from ...crypto import generate_random_string
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .discovery import (
    DiscoveryError,
    HydratedOIDCConfig,
    compute_discovery_url,
    discover_oidc_config,
    map_discovery_error_to_api_error,
    validate_skip_discovery_endpoints,
)
from .providers import has_org_admin_role
from .utils import safe_json_parse

if TYPE_CHECKING:
    from . import SSOPlugin

# Account-linking provider slugs an SSO providerId must not collide with (sso.ts).
BUILT_IN_ACCOUNT_PROVIDER_IDS = (
    "credential",
    "email-otp",
    "magic-link",
    "phone-number",
    "anonymous",
    "siwe",
)


def get_oidc_redirect_uri(plugin: SSOPlugin, ctx: Ctx, provider_id: str) -> str:
    """Shared ``redirectURI`` option (full URL or path) or the per-provider default
    ``{baseURL}/sso/callback/{providerId}`` (sso.ts ``getOIDCRedirectURI``)."""
    base_url = plugin.context_base_url(ctx)
    redirect = (plugin.redirect_uri or "").strip()
    if redirect:
        parts = urlsplit(redirect)
        if parts.scheme and parts.netloc:
            return redirect
        path = redirect if redirect.startswith("/") else f"/{redirect}"
        return f"{base_url}{path}"
    return f"{base_url}/sso/callback/{provider_id}"


def _drop_none(obj: dict[str, Any]) -> dict[str, Any]:
    """Mirror ``JSON.stringify`` dropping ``undefined`` keys."""
    return {key: value for key, value in obj.items() if value is not None}


def build_oidc_config(
    plugin: SSOPlugin,
    body: dict[str, Any],
    hydrated: HydratedOIDCConfig | None,
) -> str | None:
    """Serialize the persisted ``oidcConfig`` JSON blob (exact key order + compact
    separators = cross-runtime byte parity with TS ``buildOIDCConfig``)."""
    oidc = body.get("oidcConfig")
    if not oidc:
        return None

    override = bool(body.get("overrideUserInfo") or plugin.default_override_user_info)
    pkce = oidc.get("pkce", True)

    if oidc.get("skipDiscovery"):
        blob = {
            "issuer": body["issuer"],
            "clientId": oidc["clientId"],
            "clientSecret": oidc["clientSecret"],
            "authorizationEndpoint": oidc.get("authorizationEndpoint"),
            "tokenEndpoint": oidc.get("tokenEndpoint"),
            "tokenEndpointAuthentication": oidc.get("tokenEndpointAuthentication")
            or "client_secret_basic",
            "jwksEndpoint": oidc.get("jwksEndpoint"),
            "pkce": pkce,
            "discoveryEndpoint": oidc.get("discoveryEndpoint")
            or compute_discovery_url(body["issuer"]),
            "mapping": oidc.get("mapping"),
            "scopes": oidc.get("scopes"),
            "userInfoEndpoint": oidc.get("userInfoEndpoint"),
            "overrideUserInfo": override,
        }
    else:
        if hydrated is None:
            return None
        blob = {
            "issuer": hydrated.issuer,
            "clientId": oidc["clientId"],
            "clientSecret": oidc["clientSecret"],
            "authorizationEndpoint": hydrated.authorization_endpoint,
            "tokenEndpoint": hydrated.token_endpoint,
            "tokenEndpointAuthentication": hydrated.token_endpoint_authentication,
            "jwksEndpoint": hydrated.jwks_endpoint,
            "pkce": pkce,
            "discoveryEndpoint": hydrated.discovery_endpoint,
            "mapping": oidc.get("mapping"),
            "scopes": oidc.get("scopes"),
            "userInfoEndpoint": hydrated.user_info_endpoint,
            "overrideUserInfo": override,
        }
    return json.dumps(_drop_none(blob), separators=(",", ":"), ensure_ascii=False)


def _is_valid_url(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parts = urlsplit(value)
    return bool(parts.scheme and parts.netloc)


async def register(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    user = session["user"]

    raw_limit = plugin.providers_limit
    limit: int
    if raw_limit is None:
        limit = 10
    elif isinstance(raw_limit, int):
        limit = raw_limit
    else:
        result: Any = raw_limit(user)
        limit = await result if inspect.isawaitable(result) else result
    if not limit:
        raise APIError(403, "FORBIDDEN", "SSO provider registration is disabled")

    existing_owned = await ctx.adapter.find_many(
        plugin.model_name, [Where("userId", user["id"])]
    )
    if len(existing_owned) >= limit:
        raise APIError(403, "FORBIDDEN", "You have reached the maximum number of SSO providers")

    body = ctx.body()
    provider_id = body.get("providerId")
    issuer = body.get("issuer")
    domain = body.get("domain")
    if not isinstance(provider_id, str) or not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    if not isinstance(domain, str) or not domain:
        raise APIError(400, "BAD_REQUEST", "domain is required")
    if not isinstance(issuer, str) or not _is_valid_url(issuer):
        raise APIError(400, "BAD_REQUEST", "Invalid issuer. Must be a valid URL")

    if body.get("providerType") == "saml" or body.get("samlConfig"):
        raise APIError(400, "BAD_REQUEST", "SAML is not supported in this build")

    org_id = body.get("organizationId")
    if org_id:
        member = await ctx.adapter.find_one(
            "member",
            [Where("userId", user["id"]), Where("organizationId", org_id)],
        )
        if not member:
            raise APIError(400, "BAD_REQUEST", "You are not a member of the organization")
        if plugin.has_org_plugin(ctx) and not has_org_admin_role(member["role"]):
            raise APIError(
                403,
                "FORBIDDEN",
                "You must be an organization owner or admin to register SSO providers",
            )

    reserved = set(BUILT_IN_ACCOUNT_PROVIDER_IDS)
    reserved.update(ctx.auth.social_providers.keys())
    reserved.update(getattr(ctx.auth, "trusted_providers", []) or [])
    reserved.update(
        str(p["providerId"]) for p in plugin.default_sso if p.get("providerId")
    )
    if provider_id in reserved:
        raise APIError(
            422,
            "UNPROCESSABLE_ENTITY",
            "This providerId is reserved and cannot be used for an SSO provider",
        )

    if plugin.has_plugin(ctx, "scim"):
        existing_scim = await ctx.adapter.find_one(
            "scimProvider", [Where("providerId", provider_id)]
        )
        if existing_scim:
            raise APIError(
                422,
                "UNPROCESSABLE_ENTITY",
                "This providerId is already used by a SCIM provider and cannot be used "
                "for an SSO provider",
            )

    existing = await ctx.adapter.find_one(plugin.model_name, [Where("providerId", provider_id)])
    if existing:
        raise APIError(
            422, "UNPROCESSABLE_ENTITY", "SSO provider with this providerId already exists"
        )

    oidc = body.get("oidcConfig")
    if oidc:
        try:
            validate_skip_discovery_endpoints(oidc, ctx.auth.is_trusted_url)
        except DiscoveryError as error:
            raise map_discovery_error_to_api_error(error) from error

    hydrated: HydratedOIDCConfig | None = None
    if oidc and not oidc.get("skipDiscovery"):
        try:
            hydrated = await discover_oidc_config(
                issuer=issuer,
                existing_config={
                    "discoveryEndpoint": oidc.get("discoveryEndpoint"),
                    "authorizationEndpoint": oidc.get("authorizationEndpoint"),
                    "tokenEndpoint": oidc.get("tokenEndpoint"),
                    "jwksEndpoint": oidc.get("jwksEndpoint"),
                    "userInfoEndpoint": oidc.get("userInfoEndpoint"),
                    "tokenEndpointAuthentication": oidc.get("tokenEndpointAuthentication"),
                },
                is_trusted_origin=ctx.auth.is_trusted_url,
                http=ctx.auth.http,
            )
        except DiscoveryError as error:
            raise map_discovery_error_to_api_error(error) from error

    data: dict[str, Any] = {
        "issuer": issuer,
        "domain": domain,
        "oidcConfig": build_oidc_config(plugin, body, hydrated),
        "samlConfig": None,
        "organizationId": org_id,
        "userId": user["id"],
        "providerId": provider_id,
    }
    if plugin.domain_verification_enabled:
        data["domainVerified"] = False
    provider = await ctx.adapter.create(plugin.model_name, data)

    domain_verification_token: str | None = None
    if plugin.domain_verification_enabled:
        domain_verification_token = generate_random_string(24)
        await ctx.internal.create_verification_value(
            {
                "identifier": plugin.verification_identifier(provider_id),
                "value": domain_verification_token,
                "expiresAt": utcnow() + timedelta(days=7),
            }
        )

    result: dict[str, Any] = {
        **provider,
        "oidcConfig": safe_json_parse(provider.get("oidcConfig")),
        "samlConfig": None,
        "redirectURI": get_oidc_redirect_uri(plugin, ctx, provider_id),
    }
    if plugin.domain_verification_enabled:
        result["domainVerified"] = False
        result["domainVerificationToken"] = domain_verification_token
    return AuthResponse(body=result)
