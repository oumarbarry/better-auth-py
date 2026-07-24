"""OIDC discovery pipeline + SSRF/private-host guards.

Faithful port of ``packages/sso/src/oidc/{discovery,types,errors}.ts``. Used at
provider-registration time (to persist a validated config) and at runtime (to
hydrate legacy providers missing endpoints — Wave C).

Security posture ported verbatim:
  - Every user-supplied endpoint URL must be ``http(s)`` and either publicly
    routable (``is_public_routable_host``) OR allowlisted via ``trustedOrigins``
    (the escape hatch for internal IdPs).
  - The discovery fetch never follows redirects (a 3xx Location is not re-checked,
    so it could point at an internal host) — redirects are rejected outright.
  - Server-side-fetched hosts (token/userinfo/jwks) are additionally DNS-resolved
    and every resolved address re-classified (DNS-rebind defense). Best-effort:
    skipped for IP literals, allowlisted origins, and on resolver failure — exactly
    like TS falling back on runtimes without ``node:dns``.
  - The discovery document ``issuer`` must exactly match the configured issuer
    (trailing slash normalized).

``is_trusted_origin`` here is the plugin caller's ``trustedOrigins`` matcher
(``auth.is_trusted_url``), matching TS ``ctx.context.isTrustedOrigin``.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import SplitResult, urljoin, urlsplit

import httpx

from ...types import APIError
from .host import classify_host, is_public_routable_host

IsTrustedOrigin = Callable[[str], bool]
#: sync or async resolver: host -> list of A/AAAA address strings
ResolveHost = Callable[[str], "Awaitable[list[str]] | list[str]"]

DEFAULT_DISCOVERY_TIMEOUT = 10.0  # seconds (TS uses 10000ms)

REQUIRED_DISCOVERY_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")

# code -> APIError status name (errors.ts). All not listed here -> BAD_REQUEST.
_DISCOVERY_ERROR_STATUS: dict[str, int] = {
    "discovery_timeout": 502,
    "discovery_unexpected_error": 502,
}


class DiscoveryError(Exception):
    """OIDC discovery failure, mappable to an APIError at the HTTP boundary."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass
class HydratedOIDCConfig:
    """Normalized OIDC config after discovery (camelCase-named source fields kept as
    snake_case attrs; ``buildOIDCConfig`` reads these to persist the JSON blob)."""

    issuer: str
    discovery_endpoint: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_endpoint: str
    user_info_endpoint: str | None = None
    token_endpoint_authentication: str | None = None
    scopes_supported: list[str] | None = None


def map_discovery_error_to_api_error(error: DiscoveryError) -> APIError:
    """Map a DiscoveryError to the port-native APIError (errors.ts code->status)."""
    status = _DISCOVERY_ERROR_STATUS.get(error.code, 400)
    if error.code not in _DISCOVERY_ERROR_STATUS and error.code not in _KNOWN_400_CODES:
        status = 500
    return APIError(status, error.code, error.message)


_KNOWN_400_CODES = {
    "discovery_not_found",
    "discovery_invalid_url",
    "discovery_untrusted_origin",
    "discovery_private_host",
    "discovery_invalid_json",
    "discovery_incomplete",
    "issuer_mismatch",
    "unsupported_token_auth_method",
}


# --- URL parsing / normalization -----------------------------------------------------


def _parse_url(name: str, endpoint: str, base: str | None = None) -> SplitResult:
    """Parse ``endpoint`` (optionally resolved against ``base``); require an http(s)
    scheme and a host. Raises DiscoveryError(discovery_invalid_url) otherwise."""
    try:
        resolved = urljoin(base, endpoint) if base else endpoint
        parts = urlsplit(resolved)
    except ValueError as error:
        raise DiscoveryError(
            "discovery_invalid_url",
            f'The url "{name}" must be valid: {endpoint}',
            {"url": endpoint},
        ) from error
    if parts.scheme in ("http", "https") and parts.netloc:
        return parts
    raise DiscoveryError(
        "discovery_invalid_url",
        f'The url "{name}" must use the http or https supported protocols: {endpoint}',
        {"url": endpoint},
    )


def compute_discovery_url(issuer: str) -> str:
    base = issuer[:-1] if issuer.endswith("/") else issuer
    return f"{base}/.well-known/openid-configuration"


def normalize_url(name: str, endpoint: str, issuer: str) -> str:
    """Return ``endpoint`` as an absolute http(s) URL; if it is relative, resolve it
    against the issuer origin+path (discovery.ts ``normalizeUrl``)."""
    try:
        return _parse_url(name, endpoint).geturl()
    except DiscoveryError:
        issuer_parts = _parse_url(name, issuer)
        origin = f"{issuer_parts.scheme}://{issuer_parts.netloc}"
        base_path = issuer_parts.path.rstrip("/")
        endpoint_path = endpoint.lstrip("/")
        return _parse_url(name, f"{base_path}/{endpoint_path}", origin).geturl()


# --- SSRF gate on user-supplied endpoints (validateSkipDiscoveryEndpoint) ------------


def _validate_skip_discovery_endpoint(
    name: str, endpoint: str, is_trusted_origin: IsTrustedOrigin
) -> None:
    parsed = _parse_url(name, endpoint)
    hostname = parsed.hostname or ""
    if is_public_routable_host(hostname):
        return
    if is_trusted_origin(parsed.geturl()):
        return
    raise DiscoveryError(
        "discovery_private_host",
        f"The {name} URL ({parsed.geturl()}) is not publicly routable: {hostname}. "
        "If this is an internal IdP, add its origin to trustedOrigins.",
        {"endpoint": name, "url": endpoint, "hostname": hostname},
    )


def validate_skip_discovery_endpoints(
    config: dict[str, Any], is_trusted_origin: IsTrustedOrigin
) -> None:
    """Validate every present OIDC endpoint URL in a register/update body. Omitted
    (None/empty) fields are skipped (discovery.ts ``validateSkipDiscoveryEndpoints``)."""
    for name in (
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInfoEndpoint",
        "jwksEndpoint",
        "discoveryEndpoint",
    ):
        url = config.get(name)
        if url:
            _validate_skip_discovery_endpoint(name, url, is_trusted_origin)


def validate_discovery_url(url: str, is_trusted_origin: IsTrustedOrigin) -> None:
    """The discovery URL itself must be a trusted origin (server-side fetch target)."""
    endpoint = _parse_url("discoveryEndpoint", url).geturl()
    if not is_trusted_origin(endpoint):
        raise DiscoveryError(
            "discovery_untrusted_origin",
            f'The main discovery endpoint "{endpoint}" is not trusted by your '
            "trusted origins configuration.",
            {"url": endpoint},
        )


# --- DNS resolve-check (best-effort DNS-rebind defense) ------------------------------


async def _default_resolve_host(host: str) -> list[str]:
    """Resolve A/AAAA records via dnspython's async resolver."""
    import dns.asyncresolver  # lazy: keep the dep off the import path

    addresses: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await dns.asyncresolver.resolve(host, rdtype)
        except Exception:
            continue
        addresses.extend(str(record) for record in answer)
    if not addresses:
        raise OSError(f"no addresses resolved for {host}")
    return addresses


async def assert_endpoint_resolves_public(
    name: str,
    endpoint: str,
    is_trusted_origin: IsTrustedOrigin,
    resolve_host: ResolveHost | None = None,
) -> None:
    """Resolve the endpoint host and reject any resolved address that is not publicly
    routable. Best-effort: allowlisted origins, IP literals, and resolver failures are
    skipped (discovery.ts ``assertEndpointResolvesPublic``)."""
    parsed = _parse_url(name, endpoint)
    if is_trusted_origin(parsed.geturl()):
        return
    host = parsed.hostname or ""
    if classify_host(host).literal != "fqdn":
        return  # IP literals are already covered synchronously

    resolver = resolve_host or _default_resolve_host
    try:
        result = resolver(host)
        resolved = await result if inspect.isawaitable(result) else result
    except Exception:
        return

    addresses = cast("list[str]", resolved)
    for address in addresses:
        if not is_public_routable_host(address):
            raise DiscoveryError(
                "discovery_private_host",
                f'The {name} host "{host}" resolves to a non-publicly-routable '
                f"address ({address}). If this is an internal IdP, add its origin "
                "to trustedOrigins.",
                {"endpoint": name, "url": endpoint, "hostname": host, "resolved": address},
            )


async def assert_oidc_endpoints_resolve_public(
    config: dict[str, Any],
    is_trusted_origin: IsTrustedOrigin,
    resolve_host: ResolveHost | None = None,
) -> None:
    """Re-validate every server-side-fetched endpoint (token/userinfo/jwks) with the
    sync host check + the DNS resolve-check. ``authorizationEndpoint`` is a browser
    redirect target and intentionally excluded."""
    for name in ("tokenEndpoint", "userInfoEndpoint", "jwksEndpoint"):
        url = config.get(name)
        if not url:
            continue
        _validate_skip_discovery_endpoint(name, url, is_trusted_origin)
        await assert_endpoint_resolves_public(name, url, is_trusted_origin, resolve_host)


# --- fetch + validate + normalize ----------------------------------------------------


async def fetch_discovery_document(
    http: httpx.AsyncClient, url: str, timeout: float = DEFAULT_DISCOVERY_TIMEOUT
) -> dict[str, Any]:
    """Fetch the OIDC discovery document. Never follows redirects (a 3xx is an error)."""
    try:
        response = await http.get(url, timeout=timeout, follow_redirects=False)
    except httpx.TimeoutException as error:
        raise DiscoveryError(
            "discovery_timeout", "Discovery request timed out", {"url": url}
        ) from error
    except httpx.HTTPError as error:
        raise DiscoveryError(
            "discovery_unexpected_error",
            f"Unexpected error during discovery: {error}",
            {"url": url},
        ) from error

    status = response.status_code
    if 300 <= status < 400:
        raise DiscoveryError(
            "discovery_unexpected_error",
            "Discovery endpoint returned a redirect, which is not followed",
            {"url": url, "status": status},
        )
    if status == 404:
        raise DiscoveryError(
            "discovery_not_found", "Discovery endpoint not found", {"url": url, "status": status}
        )
    if status == 408:
        raise DiscoveryError(
            "discovery_timeout", "Discovery request timed out", {"url": url}
        )
    if status >= 400:
        raise DiscoveryError(
            "discovery_unexpected_error",
            f"Unexpected discovery error: {status}",
            {"url": url, "status": status},
        )

    try:
        data = response.json()
    except ValueError as error:
        raise DiscoveryError(
            "discovery_invalid_json", "Discovery endpoint returned invalid JSON", {"url": url}
        ) from error
    if not isinstance(data, dict) or not data:
        raise DiscoveryError(
            "discovery_invalid_json", "Discovery endpoint returned an empty response", {"url": url}
        )
    return data


def _strip_trailing_slash(value: str) -> str:
    return value[:-1] if value.endswith("/") else value


def validate_discovery_document(doc: dict[str, Any], configured_issuer: str) -> None:
    """Require all REQUIRED_DISCOVERY_FIELDS + an exact issuer match (trailing slash
    normalized) (discovery.ts ``validateDiscoveryDocument``)."""
    missing = [f for f in REQUIRED_DISCOVERY_FIELDS if not doc.get(f)]
    if missing:
        raise DiscoveryError(
            "discovery_incomplete",
            f"Discovery document is missing required fields: {', '.join(missing)}",
            {"missingFields": missing},
        )
    if _strip_trailing_slash(doc["issuer"]) != _strip_trailing_slash(configured_issuer):
        raise DiscoveryError(
            "issuer_mismatch",
            f'Discovered issuer "{doc["issuer"]}" does not match configured issuer '
            f'"{configured_issuer}"',
            {"discovered": doc["issuer"], "configured": configured_issuer},
        )


def _normalize_and_validate_url(
    name: str, endpoint: str, issuer: str, is_trusted_origin: IsTrustedOrigin
) -> str:
    url = normalize_url(name, endpoint, issuer)
    if not is_trusted_origin(url):
        raise DiscoveryError(
            "discovery_untrusted_origin",
            f'The {name} "{url}" is not trusted by your trusted origins configuration.',
            {"endpoint": name, "url": url},
        )
    return url


def normalize_discovery_urls(
    document: dict[str, Any], issuer: str, is_trusted_origin: IsTrustedOrigin
) -> dict[str, Any]:
    """Resolve+validate each endpoint in the discovery doc against the issuer origin."""
    doc = dict(document)
    for name in ("token_endpoint", "authorization_endpoint", "jwks_uri"):
        doc[name] = _normalize_and_validate_url(name, doc[name], issuer, is_trusted_origin)
    for name in (
        "userinfo_endpoint",
        "revocation_endpoint",
        "end_session_endpoint",
        "introspection_endpoint",
    ):
        if doc.get(name):
            doc[name] = _normalize_and_validate_url(name, doc[name], issuer, is_trusted_origin)
    return doc


def select_token_endpoint_auth_method(
    doc: dict[str, Any], existing: str | None = None
) -> str:
    if existing:
        return existing
    supported = doc.get("token_endpoint_auth_methods_supported")
    if not supported:
        return "client_secret_basic"
    if "client_secret_basic" in supported:
        return "client_secret_basic"
    if "client_secret_post" in supported:
        return "client_secret_post"
    return "client_secret_basic"


def needs_runtime_discovery(config: dict[str, Any] | None) -> bool:
    """True if the stored config is missing an endpoint required to complete the
    token exchange / id-token validation / authorize redirect."""
    if not config:
        return True
    return not (
        config.get("tokenEndpoint")
        and config.get("jwksEndpoint")
        and config.get("authorizationEndpoint")
    )


async def discover_oidc_config(
    *,
    issuer: str,
    is_trusted_origin: IsTrustedOrigin,
    http: httpx.AsyncClient,
    existing_config: dict[str, Any] | None = None,
    discovery_endpoint: str | None = None,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
) -> HydratedOIDCConfig:
    """Discover + hydrate OIDC config from an issuer (existing values win). Raises
    DiscoveryError on any failure (discovery.ts ``discoverOIDCConfig``)."""
    existing = existing_config or {}
    discovery_url = (
        discovery_endpoint or existing.get("discoveryEndpoint") or compute_discovery_url(issuer)
    )
    validate_discovery_url(discovery_url, is_trusted_origin)
    doc = await fetch_discovery_document(http, discovery_url, timeout)
    validate_discovery_document(doc, issuer)
    normalized = normalize_discovery_urls(doc, issuer, is_trusted_origin)
    token_auth = select_token_endpoint_auth_method(
        normalized, existing.get("tokenEndpointAuthentication")
    )
    return HydratedOIDCConfig(
        issuer=existing.get("issuer") or normalized["issuer"],
        discovery_endpoint=existing.get("discoveryEndpoint") or discovery_url,
        authorization_endpoint=existing.get("authorizationEndpoint")
        or normalized["authorization_endpoint"],
        token_endpoint=existing.get("tokenEndpoint") or normalized["token_endpoint"],
        jwks_endpoint=existing.get("jwksEndpoint") or normalized["jwks_uri"],
        user_info_endpoint=existing.get("userInfoEndpoint") or normalized.get("userinfo_endpoint"),
        token_endpoint_authentication=existing.get("tokenEndpointAuthentication") or token_auth,
        scopes_supported=existing.get("scopesSupported") or normalized.get("scopes_supported"),
    )


async def ensure_runtime_discovery(
    config: dict[str, Any],
    issuer: str,
    is_trusted_origin: IsTrustedOrigin,
    http: httpx.AsyncClient,
    resolve_host: ResolveHost | None = None,
) -> dict[str, Any]:
    """Runtime hydration for legacy/partial provider rows (Wave C sign-in/callback).
    Re-runs discovery when endpoints are missing, then runs the DNS resolve-check."""
    resolved = dict(config)
    if needs_runtime_discovery(config):
        hydrated = await discover_oidc_config(
            issuer=issuer, existing_config=config, is_trusted_origin=is_trusted_origin, http=http
        )
        resolved.update(
            authorizationEndpoint=hydrated.authorization_endpoint,
            tokenEndpoint=hydrated.token_endpoint,
            tokenEndpointAuthentication=hydrated.token_endpoint_authentication,
            userInfoEndpoint=hydrated.user_info_endpoint,
            jwksEndpoint=hydrated.jwks_endpoint,
        )
    await assert_oidc_endpoints_resolve_public(resolved, is_trusted_origin, resolve_host)
    return resolved
