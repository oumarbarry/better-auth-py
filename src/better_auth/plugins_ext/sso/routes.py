"""OIDC routes of the sso plugin: register, sign-in and the callbacks.

Port of ``packages/sso/src/routes/sso.ts`` at better-auth v1.7.6, OIDC path only.
The SAML config branch is excluded: a ``providerType:"saml"`` (or a ``samlConfig``
body) is rejected with a BAD_REQUEST rather than silently branched. ``buildOIDCConfig``
serializes the exact cross-runtime JSON blob (``clientSecret`` in plaintext; keys with
absent values dropped, mirroring ``JSON.stringify`` omitting ``undefined``).
"""

from __future__ import annotations

import inspect
import json
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from ...adapters.base import BaseAdapter, Where
from ...crypto import generate_random_string
from ...oauth.flow import (
    STATE_COOKIE,
    OAuthLinkError,
    _absolute_url,
    _additional_params,
    _create_state,
    _error_redirect,
    _parse_state,
    _state_cookie,
    _StateError,
    add_oauth_server_context,
    append_query_params,
    handle_oauth_user_info,
)
from ...oauth.machinery import (
    PRIVATE_KEY_JWT_SIGNING_ALGORITHMS,
    OAuthFetchError,
    TokenEndpointAuth,
    apply_token_endpoint_auth,
    build_authorization_url,
    create_private_key_jwt_client_assertion_getter,
    get_oauth2_tokens,
)
from ...oauth.models import OAuthTokens, OAuthUserInfo
from ...oauth.providers import ProviderConfig
from ...oauth.verify import verify_id_token
from ...schema import filter_output_fields
from ...session import clear_cookie, create_session, utcnow
from ...types import APIError, AuthResponse, Ctx
from . import org_assignment as _org
from .discovery import (
    DiscoveryError,
    HydratedOIDCConfig,
    assert_oidc_endpoint_allowed,
    compute_discovery_url,
    discover_oidc_config,
    ensure_runtime_discovery,
    fetch_oidc_endpoint,
    map_discovery_error_to_api_error,
    validate_oidc_endpoint_urls,
)
from .provider_reference import (
    SSO_PROVIDER_STATE_KEY,
    compute_sso_provider_reference,
    is_current_sso_provider_reference,
    parse_sso_provider_reference,
)
from .providers import (
    assert_token_endpoint_auth_config,
    has_org_admin_role,
    lock_sso_provider_for_account_link,
)
from .utils import (
    domain_matches,
    parse_provider_email_verified,
    safe_json_parse,
    validate_email_domain,
)

logger = logging.getLogger("better_auth")

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
            "clientSecret": oidc.get("clientSecret"),
            "authorizationEndpoint": oidc.get("authorizationEndpoint"),
            "tokenEndpoint": oidc.get("tokenEndpoint"),
            "tokenEndpointAuthentication": oidc.get("tokenEndpointAuthentication")
            or "client_secret_basic",
            "privateKeyId": oidc.get("privateKeyId"),
            "privateKeyAlgorithm": oidc.get("privateKeyAlgorithm"),
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
            "clientSecret": oidc.get("clientSecret"),
            "authorizationEndpoint": hydrated.authorization_endpoint,
            "tokenEndpoint": hydrated.token_endpoint,
            "tokenEndpointAuthentication": hydrated.token_endpoint_authentication,
            "privateKeyId": oidc.get("privateKeyId"),
            "privateKeyAlgorithm": oidc.get("privateKeyAlgorithm"),
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

    existing_owned = await ctx.adapter.find_many(plugin.model_name, [Where("userId", user["id"])])
    if len(existing_owned) >= limit:
        raise APIError(403, "FORBIDDEN", "You have reached the maximum number of SSO providers")

    body = ctx.body()
    additional_fields = plugin.parse_additional_fields(body, "create")
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
    reserved.update(str(p["providerId"]) for p in plugin.default_sso if p.get("providerId"))
    if provider_id in reserved:
        raise APIError(
            422,
            "UNPROCESSABLE_ENTITY",
            "This providerId is reserved and cannot be used for an SSO provider",
        )

    existing = await ctx.adapter.find_one(plugin.model_name, [Where("providerId", provider_id)])
    if existing:
        raise APIError(
            422, "UNPROCESSABLE_ENTITY", "SSO provider with this providerId already exists"
        )

    oidc = body.get("oidcConfig")
    if oidc:
        try:
            validate_oidc_endpoint_urls(oidc, ctx.auth.is_trusted_url)
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

    oidc_blob = build_oidc_config(plugin, body, hydrated)
    if oidc_blob:
        # TS v1.7.6 sso.ts:667-701
        assert_token_endpoint_auth_config(plugin, json.loads(oidc_blob), provider_id)
    data: dict[str, Any] = {
        "issuer": issuer,
        "domain": domain,
        **additional_fields,
        "oidcConfig": oidc_blob,
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
        **filter_output_fields(provider, plugin.additional_fields),
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
    additional_params = _additional_params(body)
    email = body.get("email")
    organization_slug = body.get("organizationSlug")
    provider_id = body.get("providerId")
    domain = body.get("domain")

    if not plugin.default_sso and not (email or organization_slug or domain or provider_id):
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

    # TS v1.7.6 sso.ts:1141-1144: the provider reference rides the server-trusted channel.
    await add_oauth_server_context(
        ctx, {SSO_PROVIDER_STATE_KEY: compute_sso_provider_reference(provider)}
    )
    state, code_verifier = await _create_state(
        ctx,
        callback_url=body.get("callbackURL") or ctx.auth.base_url,
        error_url=body.get("errorCallbackURL"),
        new_user_url=body.get("newUserCallbackURL"),
        request_sign_up=body.get("requestSignUp"),
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
        additional_params=additional_params,
    )
    response = AuthResponse(body={"url": url, "redirect": True})
    response.set_cookie(_state_cookie(ctx, state))
    return response


# --- GET /sso/callback/:providerId  and  GET /sso/callback (shared) -------------------


class _OIDCRedirect(Exception):
    """An OIDC callback failure redirected to the flow's error URL (TS
    ``redirectOIDCError``, sso.ts:1332-1339)."""

    def __init__(self, error: str, description: str | None = None):
        super().__init__(error)
        self.error = error
        self.description = description


def _with_state_cleared(ctx: Ctx, response: AuthResponse) -> AuthResponse:
    response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
    return response


def _read_string_claim(claims: dict[str, Any], claim: str) -> str | None:
    value = claims.get(claim)
    return value if isinstance(value, str) and value else None


def _map_claims(
    plugin: SSOPlugin, claims: dict[str, Any], mapping: dict[str, Any], subject: Any
) -> dict[str, Any]:
    """Map raw claims through ``config.mapping`` with OIDC defaults and
    ``mapping.extraFields``; the account id is always ``sub`` (sso.ts:1540-1590)."""
    extra = {key: claims.get(source) for key, source in (mapping.get("extraFields") or {}).items()}
    email_verified = (
        parse_provider_email_verified(claims.get(mapping.get("emailVerified") or "email_verified"))
        if plugin.trust_email_verified
        else False
    )
    return {
        **extra,
        "id": subject,
        "email": _read_string_claim(claims, mapping.get("email") or "email"),
        "emailVerified": email_verified,
        "name": _read_string_claim(claims, mapping.get("name") or "name"),
        "image": _read_string_claim(claims, mapping.get("image") or "picture"),
    }


def _subject(plugin: SSOPlugin, claims: dict[str, Any], mapping: dict[str, Any]) -> Any:
    """The account id: always ``sub`` (TS v1.7.6 sso.ts:1552, mapping.id removed), or the
    pre-1.7 ``mapping.id`` claim when ``legacy_mapping_id`` is on."""
    if plugin.legacy_mapping_id and mapping.get("id"):
        value = claims.get(mapping["id"])
        return str(value) if value not in (None, "") else None
    return _read_string_claim(claims, "sub")


def _string_field(value: Any, field: str) -> str | None:
    found = value.get(field) if isinstance(value, dict) else None
    return found if isinstance(found, str) and found else None


def _oidc_error_description(error: Any, fallback: str) -> str:
    """TS v1.7.6 sso.ts:1275-1298 ``getOIDCErrorDescription``. ``error`` is the error
    body merged with ``status``/``statusText`` (betterFetch's error shape)."""
    nested = error.get("error") if isinstance(error, dict) else None
    for source, field in (
        (nested, "error_description"),
        (error, "error_description"),
        (nested, "message"),
        (error, "message"),
        (error, "statusText"),
        (nested, "error"),
        (error, "error"),
    ):
        found = _string_field(source, field)
        if found:
            return found
    status = error.get("status") if isinstance(error, dict) else None
    if isinstance(status, int):
        return f"HTTP {status}"
    return fallback


def _fetch_error(response: httpx.Response) -> dict[str, Any]:
    """betterFetch's error object: the JSON body (when an object) plus status/statusText."""
    try:
        body = response.json()
    except ValueError:
        body = None
    return {
        **(body if isinstance(body, dict) else {}),
        "status": response.status_code,
        "statusText": response.reason_phrase,
    }


def _link_error_string(error: OAuthLinkError) -> str:
    """``handleOAuthUserInfo`` errors travel as TS writes them ("account not linked");
    the database redirect and the email check keep their underscore codes."""
    if error.error_url or error.code in ("email_not_verified", "internal_server_error"):
        return error.code
    return error.code.replace("_", " ")


async def _resolve_oidc_provider(
    plugin: SSOPlugin, adapter: Any, provider_id: str
) -> dict[str, Any] | None:
    """``defaultSSO`` first, then the ``ssoProvider`` table (sso.ts:1867-1897)."""
    default = next((p for p in plugin.default_sso if p.get("providerId") == provider_id), None)
    if default is not None:
        return _default_provider_view(plugin, default)
    return _parse_provider(
        await adapter.find_one(plugin.model_name, [Where("providerId", provider_id)])
    )


async def _token_endpoint_auth(
    plugin: SSOPlugin, provider: dict[str, Any], config: dict[str, Any]
) -> TokenEndpointAuth:
    """TS v1.7.6 sso.ts:1400-1455: basic/post, or ``private_key_jwt`` with key material
    from the ``defaultSSO`` entry, else ``resolvePrivateKey``."""
    method = config.get("tokenEndpointAuthentication")
    if method != "private_key_jwt":
        return TokenEndpointAuth(
            "client_secret_post" if method == "client_secret_post" else "client_secret_basic"
        )
    resolved: dict[str, Any] | None = None
    default = next(
        (
            p
            for p in plugin.default_sso
            if p.get("providerId") == provider["providerId"] and p.get("privateKey")
        ),
        None,
    )
    if default is not None:
        resolved = default["privateKey"]
    if not resolved and plugin.resolve_private_key is not None:
        result = plugin.resolve_private_key(
            {
                "providerId": provider["providerId"],
                "keyId": config.get("privateKeyId"),
                "issuer": config.get("issuer"),
            }
        )
        resolved = await result if inspect.isawaitable(result) else result
    if not resolved or not (resolved.get("privateKeyJwk") or resolved.get("privateKeyPem")):
        raise _OIDCRedirect("invalid_provider", "no_private_key_available")
    raw_alg = config.get("privateKeyAlgorithm") or resolved.get("algorithm")
    algorithm = raw_alg if raw_alg in PRIVATE_KEY_JWT_SIGNING_ALGORITHMS else None
    try:
        getter = create_private_key_jwt_client_assertion_getter(
            private_key_jwk=resolved.get("privateKeyJwk"),
            private_key_pem=resolved.get("privateKeyPem"),
            kid=config.get("privateKeyId") or resolved.get("kid"),
            algorithm=algorithm,
        )
    except ValueError as error:
        raise _OIDCRedirect("invalid_provider", str(error)) from None
    return TokenEndpointAuth("private_key_jwt", get_client_assertion=getter)


async def _exchange_code(
    plugin: SSOPlugin,
    ctx: Ctx,
    provider: dict[str, Any],
    config: dict[str, Any],
    code: str,
    code_verifier: str | None,
) -> OAuthTokens:
    """TS v1.7.6 sso.ts:1457-1505: ``authorizationCodeRequest`` sent through
    ``fetchOIDCEndpoint``."""
    auth = await _token_endpoint_auth(plugin, provider, config)
    token_endpoint = config["tokenEndpoint"]
    body: dict[str, Any] = {"grant_type": "authorization_code", "code": code}
    if code_verifier:
        body["code_verifier"] = code_verifier
    body["redirect_uri"] = get_oidc_redirect_uri(plugin, ctx, provider["providerId"])
    headers = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
    try:
        await apply_token_endpoint_auth(
            body,
            headers,
            client_id=config["clientId"],
            client_secret=None if auth.method == "private_key_jwt" else config.get("clientSecret"),
            token_endpoint=token_endpoint,
            grant_type="authorization_code",
            token_endpoint_auth=auth,
        )
        response = await fetch_oidc_endpoint(
            ctx.auth.http,
            "tokenEndpoint",
            token_endpoint,
            ctx.auth.is_trusted_url,
            method="POST",
            resolve_host=plugin.resolve_host,
            data=body,
            headers=headers,
        )
    except DiscoveryError as error:
        raise _OIDCRedirect("invalid_provider", error.message) from None
    except Exception as error:
        logger.error("Error validating authorization code: %s", error)
        raise _OIDCRedirect("invalid_provider", str(error) or "token_response_error") from None
    if not response.is_success:
        raise _OIDCRedirect(
            "invalid_provider",
            _oidc_error_description(_fetch_error(response), "token_response_error"),
        )
    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict) or not data:
        raise _OIDCRedirect("invalid_provider", "Token endpoint returned an empty response")
    return get_oauth2_tokens(data)


async def _verify_oidc_id_token(
    plugin: SSOPlugin, ctx: Ctx, provider: dict[str, Any], config: dict[str, Any], token: str
) -> dict[str, Any]:
    """TS v1.7.6 sso.ts:1519-1545 + discovery.ts ``validateOIDCIdToken``: JWKS signature,
    issuer, audience and the authorized-party (``azp``) rule; ``sub`` is required."""
    jwks_endpoint = config.get("jwksEndpoint")
    if not jwks_endpoint:
        raise _OIDCRedirect("invalid_provider", "jwks_endpoint_not_found")
    client_id = config["clientId"]

    def authorized_party(claims: dict[str, Any]) -> bool:
        aud = claims.get("aud")
        azp = claims.get("azp")
        multiple = isinstance(aud, list) and len(aud) > 1
        return not ((multiple and azp is None) or (azp is not None and azp != client_id))

    try:
        await assert_oidc_endpoint_allowed(
            "jwksEndpoint", jwks_endpoint, ctx.auth.is_trusted_url, plugin.resolve_host
        )
        claims = await verify_id_token(
            ctx.auth.http,
            token,
            jwks_uri=jwks_endpoint,
            audience=client_id,
            issuers=[provider["issuer"]],
            verify_claims=authorized_party,
        )
    except DiscoveryError as error:
        raise _OIDCRedirect("invalid_provider", error.message) from None
    except OAuthFetchError as error:
        # ponytail: the port's JWKS loader reports a redirect with its own message; TS
        # words it as ``oidc_endpoint_redirect``. Route JWKS through fetch_oidc_endpoint
        # if that text must match.
        raise _OIDCRedirect("invalid_provider", str(error)) from None
    if claims is None:
        raise _OIDCRedirect("invalid_provider", "token_not_verified")
    if not _read_string_claim(claims, "sub"):
        raise _OIDCRedirect("invalid_provider", "id_token_subject_missing")
    return claims


async def _fetch_user_info(
    plugin: SSOPlugin, ctx: Ctx, config: dict[str, Any], access_token: str | None
) -> dict[str, Any]:
    """TS v1.7.6 sso.ts:1552-1575."""
    try:
        response = await fetch_oidc_endpoint(
            ctx.auth.http,
            "userInfoEndpoint",
            config["userInfoEndpoint"],
            ctx.auth.is_trusted_url,
            resolve_host=plugin.resolve_host,
            headers={"authorization": f"Bearer {access_token}"},
        )
    except DiscoveryError as error:
        raise _OIDCRedirect("invalid_provider", error.message) from None
    if not response.is_success:
        error = _fetch_error(response)
        raise _OIDCRedirect(
            "invalid_provider",
            _string_field(error, "message")
            or _string_field(error, "statusText")
            or "userinfo_response_error",
        )
    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise _OIDCRedirect("invalid_provider", "userinfo_response_not_found")
    return data


def _is_user_resolution(value: Any) -> bool:
    """TS v1.7.6 user-resolution.ts:34-48 ``isSSOUserResolution``."""
    if not isinstance(value, dict):
        return False
    action = value.get("action")
    if action == "continue":
        return True
    if action == "link":
        user_id = value.get("userId")
        return (
            isinstance(user_id, str)
            and bool(user_id.strip())
            and value.get("profile") in ("preserve", "update")
        )
    code = value.get("code")
    return (
        action == "reject"
        and isinstance(code, str)
        and bool(code.strip())
        and (value.get("message") is None or isinstance(value.get("message"), str))
    )


async def _resolve_sso_user(
    plugin: SSOPlugin, data: dict[str, Any], database: Any
) -> dict[str, Any]:
    """TS v1.7.6 user-resolution.ts:66-86: a throwing or malformed resolver fails closed."""
    failure = APIError(500, "SSO_USER_RESOLUTION_FAILED", "Unable to resolve the SSO user")
    assert plugin.resolve_user is not None
    try:
        result = plugin.resolve_user(data, {"database": database})
        resolution = await result if inspect.isawaitable(result) else result
    except Exception:
        logger.error("SSO user resolution failed")
        raise failure from None
    if not _is_user_resolution(resolution):
        logger.error("SSO user resolver returned an invalid decision")
        raise failure
    return resolution


def _assert_native_transactions(ctx: Ctx, code: str, message: str) -> None:
    """TS v1.7.6 user-resolution.ts:99-109: the adapter must run real transactions."""
    if type(ctx.adapter).transaction is BaseAdapter.transaction:
        raise APIError(501, code, message)


def _assert_user_resolution_supported(ctx: Ctx) -> None:
    """TS v1.7.6 sso.ts:1663-1667. The async-context check always holds in Python
    (context variables)."""
    _assert_native_transactions(
        ctx,
        "SSO_USER_RESOLUTION_REQUIRES_NATIVE_TRANSACTIONS",
        "SSO user resolution requires a database adapter with native transaction support",
    )
    # user-resolution.ts:139-155: sessions must live in the database
    if ctx.auth.secondary_storage is not None and not ctx.internal.store_session_in_database:
        raise APIError(
            501,
            "SSO_USER_RESOLUTION_REQUIRES_DATABASE_SESSIONS",
            "SSO user resolution requires database-backed sessions with database fallback",
        )


async def handle_oidc_callback(
    plugin: SSOPlugin,
    ctx: Ctx,
    provider_id: str,
    state_data: dict[str, Any],
    reference: dict[str, Any] | None = None,
) -> AuthResponse:
    """Shared OIDC callback core (TS v1.7.6 sso.ts:1305-1837). ``state_data`` is the
    parsed state; ``provider_id`` comes from the path or the state's provider reference."""
    callback_url = state_data.get("callbackURL") or "/"
    error_url = state_data.get("errorURL") or callback_url
    try:
        return _with_state_cleared(
            ctx, await _complete_oidc_callback(plugin, ctx, provider_id, state_data, reference)
        )
    except _OIDCRedirect as redirect:
        params = {"error": redirect.error}
        if redirect.description:
            params["error_description"] = redirect.description
        target = redirect.url if isinstance(redirect, _OIDCRedirectTo) else error_url
        return _with_state_cleared(
            ctx, AuthResponse(redirect_to=append_query_params(target, params))
        )


async def _complete_oidc_callback(
    plugin: SSOPlugin,
    ctx: Ctx,
    provider_id: str,
    state_data: dict[str, Any],
    reference: dict[str, Any] | None,
) -> AuthResponse:
    params = dict(ctx.request.query)
    accepted = reference or parse_sso_provider_reference(
        (state_data.get("serverContext") or {}).get(SSO_PROVIDER_STATE_KEY)
    )
    callback_url = state_data.get("callbackURL") or "/"
    code = params.get("code")
    error = params.get("error")
    if not code or error:
        raise _OIDCRedirect(
            error or "invalid_request",
            params.get("error_description") or (error or "authorization_code_not_found"),
        )

    provider = await _resolve_oidc_provider(plugin, ctx.adapter, provider_id)
    if provider is None:
        raise _OIDCRedirect("invalid_provider", "provider not found")
    if accepted is None:
        raise _OIDCRedirect("invalid_state", "missing_sso_provider_reference")
    if not is_current_sso_provider_reference(provider, accepted):
        raise _OIDCRedirect("invalid_state", "sso_provider_changed_during_authentication")

    if plugin.domain_verification_enabled and not provider.get("domainVerified"):
        raise APIError(401, "UNAUTHORIZED", "Provider domain has not been verified")

    config = provider.get("oidcConfig")
    if not config:
        raise _OIDCRedirect("invalid_provider", "provider not found")
    try:
        config = await ensure_runtime_discovery(
            config, provider["issuer"], ctx.auth.is_trusted_url, ctx.auth.http, plugin.resolve_host
        )
    except DiscoveryError as discovery_error:
        raise _OIDCRedirect("discovery_failed", discovery_error.message) from None
    except Exception:
        raise _OIDCRedirect("discovery_failed", "unexpected_discovery_error") from None
    if not config.get("tokenEndpoint"):
        raise _OIDCRedirect("invalid_provider", "token_endpoint_not_found")

    tokens = await _exchange_code(
        plugin,
        ctx,
        provider,
        config,
        code,
        state_data.get("codeVerifier") if config.get("pkce") else None,
    )

    mapping = config.get("mapping") or {}
    verified: dict[str, Any] | None = None
    if tokens.id_token:
        verified = await _verify_oidc_id_token(plugin, ctx, provider, config, tokens.id_token)
    if plugin.resolve_user is not None and verified is None:
        raise _OIDCRedirect("invalid_provider", "id_token_required_for_user_resolution")

    if config.get("userInfoEndpoint"):
        raw_profile = await _fetch_user_info(plugin, ctx, config, tokens.access_token)
        if verified is not None and raw_profile.get("sub") != verified.get("sub"):
            raise _OIDCRedirect("invalid_provider", "id_token_userinfo_subject_mismatch")
        user_info = _map_claims(
            plugin, raw_profile, mapping, _subject(plugin, raw_profile, mapping)
        )
    elif verified is not None:
        raw_profile = verified
        user_info = _map_claims(plugin, verified, mapping, _subject(plugin, verified, mapping))
    else:
        raise _OIDCRedirect("invalid_provider", "user_info_endpoint_not_found")

    if not user_info.get("email") or not user_info.get("id"):
        raise _OIDCRedirect("invalid_provider", "missing_user_info")
    account_id = str(user_info["id"])
    provider_user = {
        **{k: v for k, v in user_info.items() if k != "id"},
        "email": user_info["email"],
        "name": user_info["name"] if isinstance(user_info.get("name"), str) else "",
        "image": user_info["image"] if isinstance(user_info.get("image"), str) else None,
        "emailVerified": user_info.get("emailVerified") is True
        if plugin.trust_email_verified
        else False,
    }
    account_key = {
        "issuer": (verified and _read_string_claim(verified, "iss")) or provider["issuer"],
        "accountId": account_id,
    }
    is_trusted_provider = provider.get("domainVerified") is True and validate_email_domain(
        user_info["email"], provider["domain"]
    )
    sso_provider = ProviderConfig(client_id=config["clientId"], provider_id=provider["providerId"])
    info = OAuthUserInfo(
        id=account_id,
        email=provider_user["email"],
        name=provider_user["name"],
        image=provider_user["image"],
        email_verified=provider_user["emailVerified"],
        raw=raw_profile,
    )
    resolving = plugin.resolve_user is not None
    request_sign_up = state_data.get("requestSignUp")

    async def authenticate(tx: Any) -> tuple[str, bool, list[str]] | OAuthLinkError:
        # TS v1.7.6 sso.ts:1670-1690: lock the row, then confirm the accepted reference.
        await lock_sso_provider_for_account_link(plugin, tx.adapter, provider)
        current = await _resolve_oidc_provider(plugin, tx.adapter, provider_id)
        if current is None or not is_current_sso_provider_reference(current, accepted):
            raise APIError(
                409,
                "SSO_PROVIDER_CHANGED",
                "SSO provider changed while account linking was in progress",
            )
        resolution = None
        if resolving:
            resolution = await _resolve_sso_user(
                plugin,
                {
                    "protocol": "oidc",
                    "providerId": provider["providerId"],
                    "accountKey": account_key,
                    "providerUser": provider_user,
                    "providerClaims": raw_profile or {},
                    "verifiedIdTokenClaims": verified or {},
                    "providerReference": accepted,
                },
                tx.adapter,
            )
        if resolution is not None and resolution["action"] == "reject":
            raise APIError(403, resolution["code"], resolution.get("message"))
        selected = (
            {"userId": resolution["userId"], "profile": resolution["profile"]}
            if resolution is not None and resolution["action"] == "link"
            else None
        )
        try:
            user_id, is_register = await handle_oauth_user_info(
                ctx,
                sso_provider,
                info,
                tokens,
                disable_sign_up=bool(plugin.disable_implicit_sign_up and not request_sign_up),
                is_trusted_provider=is_trusted_provider,
                # SSO provider ids are user-controlled and share the social namespace:
                # trust comes only from verified domain ownership, never the name list.
                trust_provider_by_name=False,
                override_user_info=bool(config.get("overrideUserInfo")),
                source={
                    "method": "sso-oidc",
                    "sso": {"providerId": provider["providerId"], "profile": raw_profile},
                },
                callback_url=callback_url,
                selected_user=selected,
                defer_non_database_writes=resolving,
                require_exact_account_binding=resolving,
            )
        except OAuthLinkError as link_error:
            if resolving:
                raise  # rolls the resolved binding back (requireSuccessfulSSOAuthentication)
            return link_error
        _session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
        return user_id, is_register, cookies

    try:
        if resolving:
            _assert_user_resolution_supported(ctx)
        outcome = await ctx.internal.transaction(authenticate)
    except OAuthLinkError as link_error:
        outcome = link_error
    except APIError as api_error:
        raise _OIDCRedirect(api_error.code, api_error.message) from None
    if isinstance(outcome, OAuthLinkError):
        if outcome.error_url:
            raise _OIDCRedirectTo(outcome.error_url, outcome.code)
        raise _OIDCRedirect(_link_error_string(outcome))
    user_id, is_register, cookies = outcome
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
            "accountId": account_id,
            "email": user_info["email"],
            "emailVerified": bool(user_info.get("emailVerified")),
            "rawAttributes": user_info,
        },
        provider=provider,
        token=tokens,
    )

    target = (state_data.get("newUserURL") or callback_url) if is_register else callback_url
    response = AuthResponse(redirect_to=_absolute_url(ctx, target))
    for cookie in cookies:
        response.set_cookie(cookie)
    return response


class _OIDCRedirectTo(_OIDCRedirect):
    """A database failure: TS redirects straight to ``onAPIError.errorURL``."""

    def __init__(self, url: str, error: str):
        super().__init__(error)
        self.url = url


async def _parse_callback_state(
    ctx: Ctx,
) -> tuple[dict[str, Any] | None, AuthResponse | None]:
    """TS v1.7.6 oauth2/state.ts:84-117 ``parseState``: state failures redirect to the
    default error page (or the flow's own error URL once the row was read)."""
    state = ctx.request.query.get("state")
    if not state:
        return None, _error_redirect(ctx, "state_not_found", None)
    try:
        return await _parse_state(ctx, state), None
    except _StateError as error:
        response = _error_redirect(ctx, error.code, error.error_url)
        if error.cookie_expired:
            response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
        return None, response


async def _bounce_if_idp_initiated(
    plugin: SSOPlugin, ctx: Ctx, provider_id: str
) -> AuthResponse | None:
    """TS v1.7.6 sso.ts:1903-1953 (03e6c94e9): a stateless callback for a provider that
    opted in (``oidcConfig.allowIdpInitiated``) restarts the flow with fresh state."""
    provider = await _resolve_oidc_provider(plugin, ctx.adapter, provider_id)
    config = (provider or {}).get("oidcConfig") or {}
    if provider is None or not config.get("allowIdpInitiated"):
        return None
    try:
        config = await ensure_runtime_discovery(
            config, provider["issuer"], ctx.auth.is_trusted_url, ctx.auth.http, plugin.resolve_host
        )
    except DiscoveryError:
        logger.error("IDP-initiated bounce skipped: OIDC discovery failed")
        return None
    if not config.get("authorizationEndpoint"):
        logger.error("IDP-initiated bounce skipped: authorizationEndpoint missing after discovery")
        return None
    await add_oauth_server_context(
        ctx, {SSO_PROVIDER_STATE_KEY: compute_sso_provider_reference(provider)}
    )
    state, code_verifier = await _create_state(
        ctx, callback_url=ctx.auth.base_url, error_url=None, new_user_url=None
    )
    url = build_authorization_url(
        authorization_endpoint=config["authorizationEndpoint"],
        client_id=config["clientId"],
        state=state,
        redirect_uri=get_oidc_redirect_uri(plugin, ctx, provider["providerId"]),
        scopes=config.get("scopes") or list(DEFAULT_SCOPES),
        code_verifier=code_verifier if config.get("pkce") else None,
    )
    response = AuthResponse(redirect_to=url)
    response.set_cookie(_state_cookie(ctx, state))
    return response


async def callback_sso(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    provider_id = ctx.params.get("providerId", "")
    if ctx.request.query.get("state") is None and ctx.request.query.get("code"):
        bounce = await _bounce_if_idp_initiated(plugin, ctx, provider_id)
        if bounce is not None:
            return bounce
    data, redirect = await _parse_callback_state(ctx)
    if redirect is not None:
        return redirect
    assert data is not None
    return await handle_oidc_callback(plugin, ctx, provider_id, data)


async def callback_sso_shared(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    """TS v1.7.6 sso.ts:1974-2024: the provider comes from the state's reference."""
    data, redirect = await _parse_callback_state(ctx)
    if redirect is not None:
        return redirect
    assert data is not None
    reference = parse_sso_provider_reference(
        (data.get("serverContext") or {}).get(SSO_PROVIDER_STATE_KEY)
    )
    if reference is None:
        error_url = data.get("errorURL") or data.get("callbackURL") or "/"
        return _with_state_cleared(
            ctx,
            AuthResponse(
                redirect_to=append_query_params(
                    error_url,
                    {
                        "error": "invalid_state",
                        "error_description": "missing_sso_provider_reference",
                    },
                )
            ),
        )
    return await handle_oidc_callback(plugin, ctx, reference["providerId"], data, reference)
