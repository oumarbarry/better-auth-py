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
from urllib.parse import urlencode, urlsplit

import httpx

from ...adapters.base import Where
from ...crypto import generate_random_string, unsign_value
from ...oauth.flow import (
    STATE_COOKIE,
    OAuthLinkError,
    _absolute_url,
    _create_state,
    _state_cookie,
    handle_oauth_user_info,
)
from ...oauth.machinery import OAuthFetchError, build_authorization_url, exchange_code, oauth_fetch
from ...oauth.models import OAuthUserInfo
from ...oauth.providers import ProviderConfig
from ...oauth.verify import verify_id_token
from ...session import clear_cookie, cookie_name, create_session, utcnow
from ...types import APIError, AuthResponse, Ctx
from . import org_assignment as _org
from .discovery import (
    DiscoveryError,
    HydratedOIDCConfig,
    compute_discovery_url,
    discover_oidc_config,
    ensure_runtime_discovery,
    map_discovery_error_to_api_error,
    validate_skip_discovery_endpoints,
)
from .providers import has_org_admin_role
from .utils import (
    domain_matches,
    parse_provider_email_verified,
    safe_json_parse,
    validate_email_domain,
)

DEFAULT_SCOPES = ["openid", "email", "profile", "offline_access"]

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


# --- POST /sign-in/sso ---------------------------------------------------------------


def _parse_provider(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Deserialize the stored ``oidcConfig``/``samlConfig`` JSON (sso.ts ``parseProvider``)."""
    if not row:
        return None
    return {
        **row,
        "oidcConfig": safe_json_parse(row.get("oidcConfig")) or None,
        "samlConfig": safe_json_parse(row.get("samlConfig")) or None,
    }


def _default_provider_view(plugin: SSOPlugin, default: dict[str, Any]) -> dict[str, Any]:
    """In-memory ``defaultSSO`` entry as a provider view (sso.ts:1125). Treated as
    ``domainVerified: true`` when domain verification is enabled."""
    oidc = default.get("oidcConfig")
    view: dict[str, Any] = {
        "issuer": (oidc or {}).get("issuer") or "",
        "providerId": default.get("providerId"),
        "userId": "default",
        "oidcConfig": oidc,
        "samlConfig": default.get("samlConfig"),
        "domain": default.get("domain"),
    }
    if plugin.domain_verification_enabled:
        view["domainVerified"] = True
    return view


async def sign_in_sso(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    body = ctx.body()
    email = body.get("email")
    organization_slug = body.get("organizationSlug")
    provider_id = body.get("providerId")
    domain = body.get("domain")

    if not plugin.default_sso and not (
        email or organization_slug or domain or provider_id
    ):
        raise APIError(
            400, "BAD_REQUEST", "email, organizationSlug, domain or providerId is required"
        )

    if not domain and email and "@" in email:
        domain = email.split("@")[1]

    org_id = ""
    if organization_slug:
        org = await ctx.adapter.find_one("organization", [Where("slug", organization_slug)])
        org_id = org["id"] if org else ""

    provider: dict[str, Any] | None = None
    if plugin.default_sso:
        if provider_id:
            matching = next(
                (p for p in plugin.default_sso if p.get("providerId") == provider_id), None
            )
        else:
            matching = next(
                (
                    p
                    for p in plugin.default_sso
                    if domain and domain_matches(domain, p.get("domain") or "")
                ),
                None,
            )
        if matching:
            provider = _default_provider_view(plugin, matching)

    if not provider_id and not org_id and not domain:
        raise APIError(400, "BAD_REQUEST", "providerId, orgId or domain is required")

    if provider is None:
        if provider_id or org_id:
            field = "providerId" if provider_id else "organizationId"
            provider = _parse_provider(
                await ctx.adapter.find_one(plugin.model_name, [Where(field, provider_id or org_id)])
            )
        elif domain:
            provider = _parse_provider(
                await ctx.adapter.find_one(plugin.model_name, [Where("domain", domain)])
            )
            if provider is None:
                all_providers = await ctx.adapter.find_many(plugin.model_name)
                match = next(
                    (p for p in all_providers if domain_matches(domain, p["domain"])), None
                )
                provider = _parse_provider(match)

    if provider is None:
        raise APIError(404, "NOT_FOUND", "No provider found for the issuer")

    provider_type = body.get("providerType")
    if provider_type == "oidc" and not provider.get("oidcConfig"):
        raise APIError(400, "BAD_REQUEST", "OIDC provider is not configured")
    if provider_type == "saml" and not provider.get("samlConfig"):
        raise APIError(400, "BAD_REQUEST", "SAML provider is not configured")

    if plugin.domain_verification_enabled and not provider.get("domainVerified"):
        raise APIError(401, "UNAUTHORIZED", "Provider domain has not been verified")

    config = provider.get("oidcConfig")
    if not config or provider_type == "saml":
        raise APIError(404, "NOT_FOUND", "No provider found for the issuer")

    try:
        config = await ensure_runtime_discovery(
            config, provider["issuer"], ctx.auth.is_trusted_url, ctx.auth.http, plugin.resolve_host
        )
    except DiscoveryError as error:
        raise map_discovery_error_to_api_error(error) from error
    if not config.get("authorizationEndpoint"):
        raise APIError(
            400, "BAD_REQUEST", "Invalid OIDC configuration. Authorization URL not found."
        )

    additional: dict[str, Any] = {}
    if (plugin.redirect_uri or "").strip():
        additional["ssoProviderId"] = provider["providerId"]
    if body.get("requestSignUp") is not None:
        additional["requestSignUp"] = body.get("requestSignUp")

    state, code_verifier = await _create_state(
        ctx,
        callback_url=body.get("callbackURL") or ctx.auth.base_url,
        error_url=body.get("errorCallbackURL"),
        new_user_url=body.get("newUserCallbackURL"),
        additional_data=additional or None,
    )

    scopes = body.get("scopes") or config.get("scopes") or list(DEFAULT_SCOPES)
    url = build_authorization_url(
        authorization_endpoint=config["authorizationEndpoint"],
        client_id=config["clientId"],
        state=state,
        redirect_uri=get_oidc_redirect_uri(plugin, ctx, provider["providerId"]),
        scopes=scopes,
        code_verifier=code_verifier if config.get("pkce") else None,
        login_hint=body.get("loginHint") or email,
    )
    response = AuthResponse(body={"url": url, "redirect": True})
    response.set_cookie(_state_cookie(ctx, state))
    return response


# --- GET /sso/callback/:providerId  and  GET /sso/callback (shared) -------------------


def _default_error_url(ctx: Ctx) -> str:
    return ctx.auth.on_api_error.error_url or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"


def _redirect_error(error_url: str, error: str, description: str | None = None) -> AuthResponse:
    """302 to ``error_url`` with ``?error=`` (+ ``error_description``), choosing the
    ``?``/``&`` separator (sso.ts callback redirects / generic-oauth ``redirectOnError``)."""
    params = {"error": error}
    if description:
        params["error_description"] = description
    sep = "&" if "?" in error_url else "?"
    return AuthResponse(redirect_to=f"{error_url}{sep}{urlencode(params)}")


def _with_state_cleared(ctx: Ctx, response: AuthResponse) -> AuthResponse:
    response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
    return response


def _apply_mapping(
    claims: dict[str, Any], mapping: dict[str, Any], *, trust_email_verified: bool
) -> dict[str, Any]:
    """Map raw claims (userinfo or verified id-token) through ``config.mapping`` with OIDC
    defaults + ``mapping.extraFields`` (sso.ts:1605)."""
    extra = {
        key: claims.get(source) for key, source in (mapping.get("extraFields") or {}).items()
    }
    return {
        **extra,
        "id": claims.get(mapping.get("id") or "sub"),
        "email": claims.get(mapping.get("email") or "email"),
        "emailVerified": (
            parse_provider_email_verified(
                claims.get(mapping.get("emailVerified") or "email_verified")
            )
            if trust_email_verified
            else False
        ),
        "name": claims.get(mapping.get("name") or "name"),
        "image": claims.get(mapping.get("image") or "picture"),
    }


async def _resolve_user_info(
    ctx: Ctx, plugin: SSOPlugin, config: dict[str, Any], tokens: Any, provider: dict[str, Any]
) -> dict[str, Any] | str:
    """Resolve the profile: userinfo bearer-fetch (mapped) or id-token JWKS-verify (mapped).
    Returns the mapped userInfo dict, or a redirect error code string on failure."""
    mapping = config.get("mapping") or {}
    trust = plugin.trust_email_verified

    if config.get("userInfoEndpoint"):
        try:
            response = await oauth_fetch(
                ctx.auth.http,
                "GET",
                config["userInfoEndpoint"],
                headers={"authorization": f"Bearer {tokens.access_token}"},
            )
            response.raise_for_status()
            raw = response.json()
        except (OAuthFetchError, httpx.HTTPError, ValueError):
            return "invalid_provider"
        return _apply_mapping(raw, mapping, trust_email_verified=trust)

    if tokens.id_token:
        if not config.get("jwksEndpoint"):
            return "jwks_endpoint_not_found"
        verified = await verify_id_token(
            ctx.auth.http,
            tokens.id_token,
            jwks_uri=config["jwksEndpoint"],
            audience=config["clientId"],
            issuers=[provider["issuer"]],
        )
        if verified is None:
            return "token_not_verified"
        return _apply_mapping(verified, mapping, trust_email_verified=trust)

    return "user_info_endpoint_not_found"


async def handle_oidc_callback(
    plugin: SSOPlugin,
    ctx: Ctx,
    provider_id: str,
    state_data: dict[str, Any],
) -> AuthResponse:
    """Shared OIDC callback core (sso.ts:1449). ``state_data`` is the already-consumed
    state row payload; ``provider_id`` comes from the path or ``state.ssoProviderId``."""
    params = dict(ctx.request.query)
    callback_url = state_data.get("callbackURL") or "/"
    error_url = state_data.get("errorURL") or callback_url
    additional = state_data.get("additionalData") or {}
    request_sign_up = additional.get("requestSignUp")

    code = params.get("code")
    if not code or params.get("error"):
        return _with_state_cleared(
            ctx,
            _redirect_error(error_url, params.get("error") or "", params.get("error_description")),
        )

    # --- resolve provider (defaultSSO -> DB, by providerId) -------------------------------
    provider: dict[str, Any] | None = None
    default_match = next(
        (p for p in plugin.default_sso if p.get("providerId") == provider_id), None
    )
    if default_match is not None:
        provider = _default_provider_view(plugin, default_match)
    else:
        provider = _parse_provider(
            await ctx.adapter.find_one(plugin.model_name, [Where("providerId", provider_id)])
        )
    if provider is None:
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "invalid_provider", "provider not found")
        )

    if plugin.domain_verification_enabled and not provider.get("domainVerified"):
        raise APIError(401, "UNAUTHORIZED", "Provider domain has not been verified")

    config = provider.get("oidcConfig")
    if not config:
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "invalid_provider", "provider not found")
        )

    try:
        config = await ensure_runtime_discovery(
            config, provider["issuer"], ctx.auth.is_trusted_url, ctx.auth.http, plugin.resolve_host
        )
    except DiscoveryError as error:
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "discovery_failed", error.message)
        )
    # ponytail: TS defaults config.scopes here, but the callback never reads scopes after
    # the token exchange (they only matter on the authorize URL, built at sign-in) — dropped.
    if not config.get("tokenEndpoint"):
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "invalid_provider", "token_endpoint_not_found")
        )

    # --- token exchange -------------------------------------------------------------------
    authentication = (
        "post" if config.get("tokenEndpointAuthentication") == "client_secret_post" else "basic"
    )
    try:
        tokens = await exchange_code(
            ctx.auth.http,
            token_endpoint=config["tokenEndpoint"],
            code=code,
            redirect_uri=get_oidc_redirect_uri(plugin, ctx, provider["providerId"]),
            client_id=config["clientId"],
            client_secret=config.get("clientSecret") or "",
            code_verifier=state_data.get("codeVerifier") if config.get("pkce") else None,
            authentication=authentication,
        )
    except (OAuthFetchError, httpx.HTTPError, ValueError):
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "invalid_provider", "token_response_not_found")
        )

    # --- resolve profile ------------------------------------------------------------------
    resolved = await _resolve_user_info(ctx, plugin, config, tokens, provider)
    if isinstance(resolved, str):
        return _with_state_cleared(ctx, _redirect_error(error_url, "invalid_provider", resolved))
    user_info = resolved
    if not user_info.get("email") or not user_info.get("id"):
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "invalid_provider", "missing_user_info")
        )

    is_trusted_provider = bool(provider.get("domainVerified")) and validate_email_domain(
        user_info["email"], provider["domain"]
    )

    sso_provider = ProviderConfig(
        client_id=config["clientId"], provider_id=provider["providerId"]
    )
    info = OAuthUserInfo(
        id=str(user_info["id"]),
        email=user_info["email"],
        name=user_info.get("name") or "",
        image=user_info.get("image"),
        email_verified=(
            bool(user_info.get("emailVerified")) if plugin.trust_email_verified else False
        ),
        raw=user_info,
    )
    disable_sign_up = bool(plugin.disable_implicit_sign_up and not request_sign_up)
    try:
        user_id, is_register = await handle_oauth_user_info(
            ctx,
            sso_provider,
            info,
            tokens,
            disable_sign_up=disable_sign_up,
            is_trusted_provider=is_trusted_provider,
            trust_provider_by_name=False,
            override_user_info=bool(config.get("overrideUserInfo")),
        )
    except OAuthLinkError as error:
        return _with_state_cleared(
            ctx, _redirect_error(error_url, error.code.replace(" ", "_"))
        )
    except APIError as error:
        return _with_state_cleared(ctx, _redirect_error(error_url, error.code, error.message))

    user = await ctx.adapter.find_one("user", [Where("id", user_id)])

    if plugin.provision_user is not None and (is_register or plugin.provision_user_on_every_login):
        result = plugin.provision_user(
            {"user": user, "userInfo": user_info, "token": tokens, "provider": provider}
        )
        if inspect.isawaitable(result):
            await result

    await _org.assign_organization_from_provider(
        ctx,
        plugin,
        user=user or {"id": user_id},
        profile={
            "providerType": "oidc",
            "providerId": provider["providerId"],
            "accountId": user_info["id"],
            "email": user_info["email"],
            "emailVerified": bool(user_info.get("emailVerified")),
            "rawAttributes": user_info,
        },
        provider=provider,
        token=tokens,
    )

    _session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
    target = (
        (state_data.get("newUserURL") or callback_url) if is_register else callback_url
    )
    response = AuthResponse(redirect_to=_absolute_url(ctx, target))
    for cookie in [*cookies, clear_cookie(ctx.auth, STATE_COOKIE)]:
        response.set_cookie(cookie)
    return response


async def _consume_state(ctx: Ctx) -> tuple[dict[str, Any] | None, AuthResponse | None]:
    """Consume the CSRF state (verification row + signed cookie). Returns (data, None) on
    success or (None, redirect) on any state failure (generic-oauth callback pattern)."""
    default_error_url = _default_error_url(ctx)
    state = ctx.request.query.get("state", "")
    row = (
        await ctx.adapter.find_one("verification", [Where("identifier", state)]) if state else None
    )
    if row is None:
        return None, _redirect_error(default_error_url, "invalid_state")
    await ctx.adapter.delete_many("verification", [Where("identifier", state)])
    data = json.loads(row["value"])
    resolved_error_url = data.get("errorURL") or data.get("callbackURL") or default_error_url
    if row["expiresAt"] <= utcnow():
        return None, _with_state_cleared(
            ctx, _redirect_error(resolved_error_url, "invalid_state")
        )
    if not ctx.auth.skip_state_cookie_check:
        raw = ctx.request.cookies().get(cookie_name(ctx.auth, STATE_COOKIE))
        if raw is None or unsign_value(ctx.auth.secret, raw) != state:
            return None, _with_state_cleared(
                ctx, _redirect_error(resolved_error_url, "state_mismatch")
            )
    return data, None


async def callback_sso(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    provider_id = ctx.params.get("providerId", "")
    data, redirect = await _consume_state(ctx)
    if redirect is not None:
        return redirect
    assert data is not None
    return await handle_oidc_callback(plugin, ctx, provider_id, data)


async def callback_sso_shared(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    data, redirect = await _consume_state(ctx)
    if redirect is not None:
        return redirect
    assert data is not None
    provider_id = (data.get("additionalData") or {}).get("ssoProviderId")
    if not provider_id:
        error_url = data.get("errorURL") or data.get("callbackURL") or _default_error_url(ctx)
        return _with_state_cleared(
            ctx, _redirect_error(error_url, "invalid_state", "missing_provider_id")
        )
    return await handle_oidc_callback(plugin, ctx, provider_id, data)
