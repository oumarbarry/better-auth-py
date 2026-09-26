"""Discovery metadata — RFC 8414 authorization-server + OIDC discovery documents.

Port of TS ``packages/oauth-provider/src/metadata.ts`` and ``authorize.ts``
(``validateIssuerUrl``) at v1.7.6. TS ``ctx.context.baseURL`` maps to
``auth.base_url + auth.base_path``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from ...types import AuthResponse
from .claims import LEVEL_0_ACR, get_supported_claims
from .dpop import DPOP_SIGNING_ALGORITHMS
from .utils import PRIVATE_KEY_JWT_SIGNING_ALGORITHMS, get_jwt_plugin, is_loopback_host

if TYPE_CHECKING:
    from ...auth import BetterAuth

#: TS METADATA_CACHE_CONTROL.
METADATA_CACHE_CONTROL = "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"


def validate_issuer_url(issuer: str) -> str:
    """HTTP->HTTPS for non-loopback, strip query/fragment/trailing slash, preserve path — TS
    ``validateIssuerUrl``. Returns the input unchanged if it is not a parseable absolute URL."""
    parts = urlsplit(issuer)
    if not parts.scheme or not parts.netloc:
        return issuer
    scheme = parts.scheme
    if scheme != "https" and not is_loopback_host(parts.netloc):
        scheme = "https"
    rebuilt = urlunsplit((scheme, parts.netloc, parts.path, "", ""))
    return rebuilt.rstrip("/")


def _base_url(auth: BetterAuth) -> str:
    return f"{auth.base_url}{auth.base_path}"


def _issuer(auth: BetterAuth, opts: Any) -> str:
    jwt_plugin = None if getattr(opts, "disable_jwt_plugin", False) else get_jwt_plugin(auth)
    raw = (getattr(jwt_plugin, "issuer", None) if jwt_plugin else None) or _base_url(auth)
    return validate_issuer_url(raw)


def build_auth_server_metadata(auth: BetterAuth, opts: Any) -> dict[str, Any]:
    """RFC 8414 authorization-server metadata — TS ``authServerMetadata`` with the OIDC-plugin
    overrides applied (scopes/DCR/public-client/grants/jwt-disabled)."""
    base = _base_url(auth)
    jwt_disabled = bool(getattr(opts, "disable_jwt_plugin", False))
    jwt_plugin = None if jwt_disabled else get_jwt_plugin(auth)

    advertised = getattr(opts, "advertised_metadata", None) or {}
    scopes_supported = advertised.get("scopes_supported") or getattr(opts, "scopes", None)
    grant_types = getattr(opts, "grant_types", None)
    dcr = bool(getattr(opts, "allow_dynamic_client_registration", False))
    public_client = bool(getattr(opts, "allow_unauthenticated_client_registration", False))

    if jwt_disabled:
        jwks_uri = None
    else:
        jwks_path = getattr(jwt_plugin, "jwks_path", "/jwks")
        jwks_uri = getattr(jwt_plugin, "remote_url", None) or f"{base}{jwks_path}"

    response_types_supported = (
        [] if (grant_types is not None and "authorization_code" not in grant_types) else ["code"]
    )
    token_endpoint_auth_methods = [
        *(["none"] if public_client else []),
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ]
    endpoint_auth_methods = ["client_secret_basic", "client_secret_post", "private_key_jwt"]
    signing_algs = list(PRIVATE_KEY_JWT_SIGNING_ALGORITHMS)
    metadata: dict[str, Any] = {
        "scopes_supported": scopes_supported,
        "issuer": _issuer(auth, opts),
        "authorization_endpoint": f"{base}/oauth2/authorize",
        "token_endpoint": f"{base}/oauth2/token",
        "jwks_uri": jwks_uri,
        "registration_endpoint": f"{base}/oauth2/register" if dcr else None,
        "introspection_endpoint": f"{base}/oauth2/introspect",
        "revocation_endpoint": f"{base}/oauth2/revoke",
        "response_types_supported": response_types_supported,
        "response_modes_supported": ["query"],
        "grant_types_supported": grant_types
        or ["authorization_code", "client_credentials", "refresh_token"],
        # private_key_jwt on every client-authenticated endpoint (TS metadata.ts:68, aebf66d8e).
        "token_endpoint_auth_methods_supported": token_endpoint_auth_methods,
        "token_endpoint_auth_signing_alg_values_supported": signing_algs,
        "introspection_endpoint_auth_methods_supported": endpoint_auth_methods,
        "introspection_endpoint_auth_signing_alg_values_supported": signing_algs,
        "revocation_endpoint_auth_methods_supported": endpoint_auth_methods,
        "revocation_endpoint_auth_signing_alg_values_supported": signing_algs,
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
        # RFC 9449 (TS metadata.ts:100, aedcb974f).
        "dpop_signing_alg_values_supported": list(
            (getattr(opts, "dpop", None) or {}).get("signingAlgorithms") or DPOP_SIGNING_ALGORITHMS
        ),
        # Logout Tokens are verified on the jwt plugin's JWKS (metadata.ts:40-42,103-104).
        "backchannel_logout_supported": not jwt_disabled,
        "backchannel_logout_session_supported": not jwt_disabled,
    }
    return {k: v for k, v in metadata.items() if v is not None}


def build_oidc_server_metadata(auth: BetterAuth, opts: Any) -> dict[str, Any]:
    """OIDC discovery metadata — TS ``oidcServerMetadata`` (extends the auth-server doc)."""
    base = _base_url(auth)
    jwt_disabled = bool(getattr(opts, "disable_jwt_plugin", False))
    jwt_plugin = None if jwt_disabled else get_jwt_plugin(auth)

    key_pair_alg = (getattr(jwt_plugin, "key_pair_config", None) or {}).get("alg")
    if key_pair_alg:
        id_token_algs = [key_pair_alg]
    elif jwt_disabled:
        id_token_algs = ["HS256"]
    else:
        id_token_algs = ["EdDSA"]

    metadata = dict(build_auth_server_metadata(auth, opts))
    metadata.update(
        {
            "claims_supported": get_supported_claims(opts),
            # TS metadata.ts:171-199 (e3125e872, a966815b1, 267229bd2).
            "claims_parameter_supported": True,
            "userinfo_endpoint": f"{base}/oauth2/userinfo",
            "subject_types_supported": ["public", "pairwise"]
            if getattr(opts, "pairwise_secret", None)
            else ["public"],
            "acr_values_supported": [LEVEL_0_ACR],
            "id_token_signing_alg_values_supported": id_token_algs,
            "end_session_endpoint": f"{base}/oauth2/end-session",
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "prompt_values_supported": ["login", "consent", "create", "select_account", "none"],
        }
    )
    return metadata


def metadata_response(body: Any, *, head: bool = False) -> AuthResponse:
    """Wrap a metadata document with the discovery cache headers — TS ``metadataResponse``.
    ``head`` returns an empty body (HEAD)."""
    return AuthResponse(
        status=200,
        body=None if head else body,
        headers=[
            ("Cache-Control", METADATA_CACHE_CONTROL),
            ("Content-Type", "application/json"),
        ],
    )
