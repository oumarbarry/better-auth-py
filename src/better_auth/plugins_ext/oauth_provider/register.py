"""Client registration: RFC 7591 wire <-> DB mapping, DCR validation, the client creation
chokepoint, protected registration, and the ``clientPrivileges`` gate.

Port of TS ``packages/oauth-provider/src/register.ts``, ``client-metadata.ts``,
``utils/initial-access-token.ts``, ``oauthClient/privileges.ts`` and
``oauthClient/client-credentials.ts`` at v1.7.6. The port has no zod body layer, so the
per-endpoint allowlists and :func:`validate_registration_body` reproduce what the TS route
schemas accept (unknown keys stripped).
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from ...adapters.base import Where
from ...origin import is_trusted_origin
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from ..jwt import to_exp_jwt
from ..sso.host import is_public_routable_host
from .resources import get_resource, resource_uri_issue
from .utils import (
    OAuthError,
    apply_client_secret_prefix,
    generate_client_id,
    generate_client_secret,
    get_supported_grant_types,
    is_loopback_ip,
    parse_client_metadata,
    resolve_ctx_secret_config,
    safe_url_issue,
    store_client_secret,
)

DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"]
NO_STORE_HEADERS = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]

#: Built-in token endpoint authentication methods, ``none`` included (extensions.ts:31).
SUPPORTED_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post", "private_key_jwt")

# --- input allowlists (replace the zod body schemas) ---------------------------------

#: ``/oauth2/create-client`` (oauthClient/index.ts:229).
_CREATE_FIELDS = (
    "redirect_uris",
    "scope",
    "client_name",
    "client_uri",
    "logo_uri",
    "contacts",
    "tos_uri",
    "policy_uri",
    "software_id",
    "software_version",
    "software_statement",
    "post_logout_redirect_uris",
    "backchannel_logout_uri",
    "backchannel_logout_session_required",
    "token_endpoint_auth_method",
    "application_type",
    "jwks",
    "jwks_uri",
    "grant_types",
    "response_types",
    "dpop_bound_access_tokens",
)
#: ``/oauth2/register`` (types/zod.ts:199 clientRegistrationRequestSchema).
_REGISTER_FIELDS = (*_CREATE_FIELDS, "subject_type", "resources", "skip_consent")
#: SERVER_ONLY ``/admin/oauth2/create-client`` (oauthClient/index.ts:24).
_ADMIN_FIELDS = (
    *_CREATE_FIELDS,
    "client_credentials_scopes",
    "client_secret_expires_at",
    "skip_consent",
    "enable_end_session",
    "require_pkce",
    "subject_type",
    "metadata",
)


def clean_client_body(body: dict[str, Any], *, variant: str) -> dict[str, Any]:
    """Allowlist a client body per endpoint variant (``register`` / ``create`` / ``admin``),
    mirroring the TS zod schemas that strip unknown keys."""
    allowed = {"register": _REGISTER_FIELDS, "admin": _ADMIN_FIELDS}.get(variant, _CREATE_FIELDS)
    return {k: v for k, v in body.items() if k in allowed and v is not None}


def _registration_issue(body: dict[str, Any]) -> tuple[str, str] | None:
    """The first zod issue of ``clientRegistrationRequestSchema`` (types/zod.ts:199) as
    ``(field, description)``, described like TS ``describeIssue`` (oauth-endpoint.ts:272)."""

    def string_list(field: str, check: Any = None) -> tuple[str, str] | None:
        value = body[field]
        if not isinstance(value, list):
            return field, f"{field} must be a array"
        for index, item in enumerate(value):
            if not isinstance(item, str):
                return f"{field}.{index}", f"{field}.{index} must be a string"
            issue = check(item) if check else None
            if issue:
                return f"{field}.{index}", f"{field}.{index}: {issue}"
        return None

    for field, value in body.items():
        issue: tuple[str, str] | None = None
        if field == "skip_consent":
            # z.never(): the issue is invalid_type with expected "never".
            issue = field, f"{field} must be a never"
        elif field in ("redirect_uris", "post_logout_redirect_uris"):
            issue = string_list(field, safe_url_issue)
            if issue is None and not value:
                issue = field, f"{field}: Too small: expected array to have >=1 items"
        elif field in ("contacts", "grant_types"):
            issue = string_list(
                field,
                lambda v: (
                    None if v.strip() else "Too small: expected string to have >=1 characters"
                ),
            )
            if issue is None and not value:
                issue = field, f"{field}: Too small: expected array to have >=1 items"
        elif field == "resources":
            issue = string_list(field, resource_uri_issue)
        elif field == "response_types":
            issue = string_list(field, lambda v: None if v == "code" else "invalid")
            if issue and issue[1].endswith(": invalid"):
                issue = issue[0], f"{issue[0]} must be one of: code"
        elif field in ("backchannel_logout_session_required", "dpop_bound_access_tokens"):
            if not isinstance(value, bool):
                issue = field, f"{field} must be a boolean"
        elif field == "application_type":
            if value not in ("web", "native"):
                issue = field, f"{field} must be one of: web, native"
        elif field == "subject_type":
            if value not in ("public", "pairwise"):
                issue = field, f"{field} must be one of: public, pairwise"
        elif field == "jwks":
            keys = value.get("keys") if isinstance(value, dict) else None
            if not isinstance(value, dict):
                issue = field, f"{field} must be a object"
            elif "keys" not in value:
                issue = "jwks.keys", "jwks.keys is required"
            elif not isinstance(keys, list):
                issue = "jwks.keys", "jwks.keys must be a array"
            elif not keys:
                issue = "jwks.keys", "jwks.keys: Too small: expected array to have >=1 items"
        elif field == "backchannel_logout_uri":
            if not isinstance(value, str):
                issue = field, f"{field} must be a string"
            elif (problem := safe_url_issue(value)) is not None:
                issue = field, f"{field}: {problem}"
        elif not isinstance(value, str):
            issue = field, f"{field} must be a string"
        elif field == "client_name" and not value.strip():
            issue = field, f"{field}: client_name cannot be empty"
        elif field == "token_endpoint_auth_method" and not value.strip():
            issue = field, f"{field}: Too small: expected string to have >=1 characters"
        if issue:
            return issue
    return None


#: TS ``errorCodesByField`` of ``/oauth2/register`` (oauth.ts:1509).
_REGISTER_ERROR_CODES = {
    "redirect_uris": "invalid_redirect_uri",
    "post_logout_redirect_uris": "invalid_redirect_uri",
    "software_statement": "invalid_software_statement",
    "resources": "invalid_target",
}


def validate_registration_body(body: dict[str, Any]) -> None:
    """Reject a registration body the TS schema rejects, with its RFC 7591 error code."""
    issue = _registration_issue(body)
    if issue:
        field, description = issue
        error = _REGISTER_ERROR_CODES.get(field.split(".", 1)[0], "invalid_client_metadata")
        raise OAuthError(400, error, description)


# --- clientPrivileges gate (oauthClient/privileges.ts) -------------------------------


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def assert_client_privileges(
    ctx: Ctx, session: dict[str, Any] | None, opts: Any, action: str
) -> None:
    """The single authorization helper for every client mutation, TS
    ``assertClientPrivileges``. UNAUTHORIZED without a session, BAD_REQUEST without headers,
    else consults ``client_privileges``; ``configure-client-credentials-scopes`` always needs a
    configured hook (privileges.ts:34)."""
    if session is None:
        raise APIError(401, "UNAUTHORIZED", "Not authenticated")
    if not ctx.request.headers:
        raise APIError(400, "BAD_REQUEST")
    client_privileges = getattr(opts, "client_privileges", None)
    if action == "configure-client-credentials-scopes" and client_privileges is None:
        raise APIError(401, "UNAUTHORIZED", "Not authorized")
    if client_privileges is not None:
        allowed = await _maybe_await(
            client_privileges(
                {
                    "headers": ctx.request.headers,
                    "action": action,
                    "session": session.get("session"),
                    "user": session.get("user"),
                }
            )
        )
        if not allowed:
            raise APIError(401, "UNAUTHORIZED", "Not authorized")


# --- client_credentials scope ceiling (oauthClient/client-credentials.ts) --------------

_USER_DELEGATED_SCOPES = frozenset({"openid", "profile", "email", "offline_access"})


def normalize_client_credentials_scopes(scopes: list[str]) -> list[str]:
    """TS ``normalizeClientCredentialsScopes``: trimmed, non-empty, deduplicated in order."""
    return list(dict.fromkeys(s.strip() for s in scopes if isinstance(s, str) and s.strip()))


def validate_client_credentials_scopes(
    scopes: list[str], grant_types: list[str], auth_method: str | None, opts: Any
) -> None:
    """TS ``validateClientCredentialsScopes`` (client-credentials.ts:22)."""
    if not scopes:
        return
    if "client_credentials" not in grant_types:
        raise OAuthError(
            400,
            "invalid_client_metadata",
            "client_credentials_scopes requires the client_credentials grant",
        )
    if auth_method == "none":
        raise OAuthError(
            400,
            "invalid_client_metadata",
            "public clients cannot be assigned client_credentials scopes",
        )
    provider_scopes = set(getattr(opts, "scopes", None) or [])
    invalid = [s for s in scopes if s not in provider_scopes or s in _USER_DELEGATED_SCOPES]
    if invalid:
        raise OAuthError(
            400,
            "invalid_scope",
            f"The following client_credentials scopes are invalid: {', '.join(invalid)}",
        )


# --- wire <-> DB mapping (register.ts:1290/1374, client-metadata.ts) ------------------

#: RFC 7591 snake_case -> DB camelCase (value passthrough).
_WIRE_TO_SCHEMA = {
    "client_id": "clientId",
    "client_secret": "clientSecret",
    "user_id": "userId",
    "client_name": "name",
    "client_uri": "uri",
    "logo_uri": "icon",
    "contacts": "contacts",
    "tos_uri": "tos",
    "policy_uri": "policy",
    "jwks_uri": "jwksUri",
    "software_id": "softwareId",
    "software_version": "softwareVersion",
    "software_statement": "softwareStatement",
    "redirect_uris": "redirectUris",
    "post_logout_redirect_uris": "postLogoutRedirectUris",
    "backchannel_logout_uri": "backchannelLogoutUri",
    "backchannel_logout_session_required": "backchannelLogoutSessionRequired",
    "token_endpoint_auth_method": "tokenEndpointAuthMethod",
    "grant_types": "grantTypes",
    "response_types": "responseTypes",
    "application_type": "applicationType",
    "disabled": "disabled",
    "skip_consent": "skipConsent",
    "enable_end_session": "enableEndSession",
    "require_pkce": "requirePKCE",
    "dpop_bound_access_tokens": "dpopBoundAccessTokens",
    "subject_type": "subjectType",
    "reference_id": "referenceId",
}

#: TS ``OPAQUE_METADATA_RESERVED_FIELDS`` (client-metadata.ts:94): record and wire names that
#: must never survive inside the opaque ``metadata`` envelope.
_RESERVED_METADATA_FIELDS = frozenset(
    {
        *_WIRE_TO_SCHEMA,
        *_WIRE_TO_SCHEMA.values(),
        "client_secret_expires_at",
        "scope",
        "client_id_issued_at",
        "jwks",
        "clientDiscoveryId",
        "scopes",
        "clientCredentialsScopes",
        "createdAt",
        "updatedAt",
        "expiresAt",
        "public",
        "type",
        "resources",
        "client_credentials_scopes",
    }
)


def strip_reserved_metadata(metadata: Any) -> dict[str, Any]:
    """TS ``stripReservedOAuthClientMetadataExtensions`` (client-metadata.ts:143)."""
    if not isinstance(metadata, dict):
        return {}
    return {k: v for k, v in metadata.items() if k not in _RESERVED_METADATA_FIELDS}


def _epoch_to_dt(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def oauth_to_schema(inp: dict[str, Any]) -> dict[str, Any]:
    """RFC 7591 wire shape -> DB ``SchemaClient``, TS ``oauthToSchema`` (register.ts:1290).
    Only the explicit ``metadata`` object (reserved names stripped) lands in the ``metadata``
    column; other unknown wire keys are dropped. ``None`` values are omitted (TS undefined is
    ignored by the adapter, so an update never nulls an untouched column)."""
    out: dict[str, Any] = {}
    for wire_key, schema_key in _WIRE_TO_SCHEMA.items():
        if wire_key in inp:
            out[schema_key] = inp[wire_key]

    scope = inp.get("scope")
    if scope is not None:
        out["scopes"] = scope.split(" ")
    jwks = inp.get("jwks")
    if jwks:
        out["jwks"] = json.dumps(jwks, separators=(",", ":"))
    expires_at = inp.get("client_secret_expires_at")
    if expires_at:  # 0/None -> omit (never-expires stays unset); value is epoch seconds
        out["expiresAt"] = _epoch_to_dt(float(expires_at))
    created_at = inp.get("client_id_issued_at")
    if created_at:
        out["createdAt"] = _epoch_to_dt(created_at)
    metadata = strip_reserved_metadata(inp.get("metadata"))
    out["metadata"] = json.dumps(metadata, separators=(",", ":")) if metadata else None
    return {k: v for k, v in out.items() if v is not None}


def schema_to_oauth(row: dict[str, Any]) -> dict[str, Any]:
    """DB ``SchemaClient`` -> RFC 7591 wire shape, TS ``schemaToOAuth`` (register.ts:1374).
    ``metadata`` is parsed, stripped of reserved names and spread first; ``client_secret`` is
    included only if present (callers null it)."""
    out: dict[str, Any] = strip_reserved_metadata(parse_client_metadata(row.get("metadata")))

    def put(key: str, value: Any) -> None:
        if value is not None:
            out[key] = value

    client_secret = row.get("clientSecret")
    put("client_id", row.get("clientId"))
    put("client_secret", client_secret)
    expires_at = row.get("expiresAt")
    _exp = round(expires_at.timestamp()) if isinstance(expires_at, datetime) else None
    if client_secret:
        out["client_secret_expires_at"] = _exp if _exp is not None else 0
    scopes = row.get("scopes")
    put("scope", " ".join(scopes) if scopes is not None else None)
    put("user_id", row.get("userId"))
    created_at = row.get("createdAt")
    if isinstance(created_at, datetime):
        out["client_id_issued_at"] = round(created_at.timestamp())
    put("client_name", row.get("name"))
    put("client_uri", row.get("uri"))
    put("logo_uri", row.get("icon"))
    put("contacts", row.get("contacts"))
    put("tos_uri", row.get("tos"))
    put("policy_uri", row.get("policy"))
    jwks = row.get("jwks")
    put("jwks", json.loads(jwks) if isinstance(jwks, str) and jwks else None)
    put("jwks_uri", row.get("jwksUri"))
    put("software_id", row.get("softwareId"))
    put("software_version", row.get("softwareVersion"))
    put("software_statement", row.get("softwareStatement"))
    out["redirect_uris"] = row.get("redirectUris") or []
    put("post_logout_redirect_uris", row.get("postLogoutRedirectUris"))
    put("backchannel_logout_uri", row.get("backchannelLogoutUri"))
    put("backchannel_logout_session_required", row.get("backchannelLogoutSessionRequired"))
    put("token_endpoint_auth_method", row.get("tokenEndpointAuthMethod"))
    put("grant_types", row.get("grantTypes"))
    put("response_types", row.get("responseTypes"))
    put("application_type", row.get("applicationType"))
    put("disabled", row.get("disabled"))
    put("skip_consent", row.get("skipConsent"))
    put("enable_end_session", row.get("enableEndSession"))
    put("require_pkce", row.get("requirePKCE"))
    put("dpop_bound_access_tokens", row.get("dpopBoundAccessTokens"))
    put("subject_type", row.get("subjectType"))
    put("reference_id", row.get("referenceId"))
    return out


# --- registration defaults (register.ts:52-100) --------------------------------------


def resolve_registration_grant_types(client: dict[str, Any]) -> list[str]:
    """TS ``resolveRegistrationGrantTypes``: default ``["authorization_code"]``; an explicit
    empty list is rejected."""
    grant_types = client.get("grant_types")
    if grant_types is None:
        return ["authorization_code"]
    if grant_types:
        return list(grant_types)
    raise OAuthError(
        400, "invalid_client_metadata", "grant_types must contain at least one grant type"
    )


def apply_registration_defaults(client: dict[str, Any]) -> dict[str, Any]:
    """TS ``applyOAuthClientRegistrationDefaults``: ``client_secret_basic``, ``web`` and the
    grant/response type defaults."""
    grant_types = resolve_registration_grant_types(client)
    response_types = client.get("response_types")
    if response_types is None and "authorization_code" in grant_types:
        response_types = ["code"]
    out = {
        **client,
        "token_endpoint_auth_method": client.get("token_endpoint_auth_method")
        or "client_secret_basic",
        "application_type": client.get("application_type") or "web",
        "grant_types": grant_types,
    }
    if response_types is not None:
        out["response_types"] = response_types
    return out


def resolve_registration_scopes(opts: Any) -> list[str]:
    """TS ``resolveClientRegistrationScopes``: the ordered union of the default registration
    scopes (``scopes`` when unset) and the allowed registration scopes."""
    defaults = getattr(opts, "client_registration_default_scopes", None) or getattr(
        opts, "scopes", None
    )
    allowed = getattr(opts, "client_registration_allowed_scopes", None) or []
    return list(dict.fromkeys([*(defaults or []), *allowed]))


# --- redirect URI policy (register.ts:102-260) ---------------------------------------

_FORBIDDEN_NATIVE_SCHEMES = frozenset({"file", "ftp", "mailto", "javascript", "data", "vbscript"})
_REVERSE_DOMAIN_SCHEME = re.compile(
    r"^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$", re.IGNORECASE
)
_RAW_HTTP_AUTHORITY = re.compile(r"^http://([^/?#]*)", re.IGNORECASE)
_ALLOWED_NATIVE_HTTP_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def _invalid_redirect_uri(description: str) -> OAuthError:
    return OAuthError(400, "invalid_redirect_uri", description)


def _raw_http_hostname(uri: str) -> str | None:
    """TS ``getRawHttpHostname``: the host exactly as written, before URL normalization."""
    match = _RAW_HTTP_AUTHORITY.match(uri)
    if not match or not match.group(1):
        return None
    host_port = match.group(1)[match.group(1).rfind("@") + 1 :]
    if host_port.startswith("["):
        end = host_port.find("]")
        return None if end < 0 else host_port[: end + 1].lower()
    return host_port.split(":")[0].lower()


def _is_loopback_hostname(host: str) -> bool:
    """TS ``isLoopbackIP(url.hostname) || hostname === "localhost"`` on a WHATWG-parsed host:
    numeric IPv4 shorthands (``127.1``) normalize before the check, as ``new URL`` does."""
    if host == "localhost" or is_loopback_ip(host):
        return True
    if re.fullmatch(r"[0-9a-fx.]+", host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host)).is_loopback
        except OSError:
            return False
    return False


def _validate_redirect_uri(uri: str, application_type: str) -> None:
    """TS ``validateClientRedirectUri`` (register.ts:170): web clients need https on a
    non-loopback host; native clients may use non-loopback https, http on the exact loopback
    hosts, or an authority-free reverse-domain private-use scheme (RFC 8252 §7)."""
    try:
        parsed = urlsplit(uri)
        host = parsed.hostname or ""
        has_userinfo = bool(parsed.username or parsed.password)
    except ValueError:
        raise _invalid_redirect_uri(f"redirect URI must be an absolute URI: {uri}") from None
    if not parsed.scheme:
        raise _invalid_redirect_uri(f"redirect URI must be an absolute URI: {uri}")
    if "#" in uri or has_userinfo:
        raise _invalid_redirect_uri(
            f"redirect URI must not include credentials or a fragment: {uri}"
        )
    scheme = parsed.scheme.lower()
    if re.fullmatch(r"localhost\.+", host, re.IGNORECASE):
        raise _invalid_redirect_uri(f"redirect URI localhost must not include trailing dots: {uri}")
    is_loopback = scheme in ("http", "https") and _is_loopback_hostname(host)

    if application_type == "web":
        if scheme != "https" or is_loopback:
            raise _invalid_redirect_uri(
                f"web clients require https redirect URIs on non-loopback hosts: {uri}"
            )
        return
    if scheme == "https":
        if is_loopback:
            raise _invalid_redirect_uri(
                f"native clients must not use https loopback redirect URIs: {uri}"
            )
        return
    if scheme == "http":
        if _raw_http_hostname(uri) not in _ALLOWED_NATIVE_HTTP_HOSTS:
            raise _invalid_redirect_uri(
                "native clients may use http only on the exact loopback hosts localhost, "
                f"127.0.0.1, or [::1]: {uri}"
            )
        return
    rest = uri[len(parsed.scheme) + 1 :]
    reverse_domain = (
        not parsed.netloc
        and rest.startswith("/")
        and not rest.startswith("//")
        and bool(_REVERSE_DOMAIN_SCHEME.match(parsed.scheme))
    )
    if scheme in _FORBIDDEN_NATIVE_SCHEMES or not reverse_domain:
        raise _invalid_redirect_uri(
            "native private-use redirect URI schemes must be well-formed reverse-domain names, "
            "omit the naming authority, and must not use a reserved scheme: "
            f"{uri}"
        )


def _invalid_metadata(description: str) -> OAuthError:
    return OAuthError(400, "invalid_client_metadata", description)


# --- DCR validation (register.ts:318 checkOAuthClient) -------------------------------


async def check_oauth_client(
    client: dict[str, Any],
    opts: Any,
    registration_source: str | None = None,
    ctx: Ctx | None = None,
) -> None:
    """Validate a client-metadata combination, TS ``checkOAuthClient``. Raises
    :class:`OAuthError` (OAuth-shaped) on any violation. ``registration_source`` is
    ``"dynamic"`` for DCR, ``"managed"`` or ``None`` otherwise.

    ponytail: the ``clientMetadataDocument`` source (the CIMD plugin's grant intersection
    and same-origin ``jwks_uri``, bb8d7c454) is not ported with that plugin."""
    client = apply_registration_defaults(client)
    auth_method = client["token_endpoint_auth_method"]
    if auth_method not in SUPPORTED_AUTH_METHODS:
        raise _invalid_metadata(f"unsupported token_endpoint_auth_method {auth_method}")
    dpop_bound = client.get("dpop_bound_access_tokens")
    if dpop_bound is not None and not isinstance(dpop_bound, bool):
        raise _invalid_metadata("dpop_bound_access_tokens must be a boolean")

    grant_types = client["grant_types"]
    response_types = client.get("response_types")
    application_type = client["application_type"]
    if application_type not in ("web", "native"):
        raise _invalid_metadata("application_type must be web or native")

    redirect_uris = client.get("redirect_uris") or []
    if "authorization_code" in grant_types and not redirect_uris:
        raise _invalid_redirect_uri(
            "Redirect URIs are required for authorization_code and implicit grant types"
        )
    for uri in redirect_uris:
        _validate_redirect_uri(uri, application_type)

    supported = set(get_supported_grant_types(opts))
    for grant_type in grant_types:
        if grant_type not in supported:
            raise _invalid_metadata(f"unsupported grant_type {grant_type}")
    if "authorization_code" in grant_types and "code" not in (response_types or []):
        raise _invalid_metadata(
            "When 'authorization_code' grant type is used, 'code' response type must be included"
        )
    if "authorization_code" not in grant_types and "code" in (response_types or []):
        raise _invalid_metadata(
            "When 'code' response type is used, 'authorization_code' grant type must be included"
        )

    subject_type = client.get("subject_type")
    if subject_type is not None:
        if subject_type not in ("public", "pairwise"):
            raise _invalid_metadata('subject_type must be "public" or "pairwise"')
        if subject_type == "pairwise" and not getattr(opts, "pairwise_secret", None):
            raise _invalid_metadata(
                "pairwise subject_type requires server pairwiseSecret configuration"
            )
        if subject_type == "pairwise" and len({urlsplit(u).netloc for u in redirect_uris}) > 1:
            raise _invalid_metadata(
                "pairwise clients with redirect_uris on different hosts require a "
                "sector_identifier_uri, which is not yet supported. All redirect_uris must "
                "share the same host."
            )

    scope = client.get("scope")
    requested = [s for s in (scope.split(" ") if scope else []) if s]
    is_registration = registration_source == "dynamic"
    allowed = (
        resolve_registration_scopes(opts) if is_registration else getattr(opts, "scopes", None)
    )
    if allowed is not None:
        valid = set(allowed)
        for sc in requested:
            if sc not in valid:
                raise OAuthError(400, "invalid_scope", f"cannot request scope {sc}")

    if is_registration and client.get("require_pkce") is False:
        raise _invalid_metadata("pkce is required for registered clients.")

    jwks = client.get("jwks")
    jwks_uri = client.get("jwks_uri")
    if jwks and jwks_uri:
        raise _invalid_metadata("jwks and jwks_uri are mutually exclusive")
    if jwks_uri:
        await _check_jwks_uri(jwks_uri, ctx)
    if jwks:
        from .client_assertion import validate_public_client_jwks

        result = validate_public_client_jwks(jwks)
        if not result["valid"]:
            raise _invalid_metadata(result["error"])
    if auth_method == "private_key_jwt" and not jwks and not jwks_uri:
        raise _invalid_metadata("private_key_jwt requires either jwks or jwks_uri")

    backchannel_uri = client.get("backchannel_logout_uri")
    if backchannel_uri is not None:
        _check_backchannel_logout_uri(backchannel_uri, opts)


async def _check_jwks_uri(jwks_uri: str, ctx: Ctx | None) -> None:
    """register.ts:540-600: HTTPS, no credentials or fragment, a public host, a trusted origin."""
    try:
        parsed = urlsplit(jwks_uri)
        has_userinfo = bool(parsed.username or parsed.password)
        host = parsed.hostname or ""
    except ValueError:
        raise _invalid_metadata("jwks_uri must be a valid URL") from None
    if not parsed.scheme or not parsed.netloc:
        raise _invalid_metadata("jwks_uri must be a valid URL")
    if parsed.scheme.lower() != "https":
        raise _invalid_metadata("jwks_uri must use HTTPS")
    if has_userinfo:
        raise _invalid_metadata("jwks_uri must not contain credentials")
    if "#" in jwks_uri:
        raise _invalid_metadata("jwks_uri must not include a fragment component")
    if not is_public_routable_host(host):
        raise _invalid_metadata("jwks_uri must not point to a private or reserved address")
    if ctx is not None and not await is_trusted_origin(
        ctx.auth, ctx.request, jwks_uri, allow_relative=False
    ):
        raise _invalid_metadata(
            "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin"
        )


def _check_backchannel_logout_uri(uri: str, opts: Any) -> None:
    """register.ts:625-690: jwt plugin required (logout tokens are signed JWTs), absolute
    https, no fragment or credentials, and a publicly routable host (SSRF guard)."""
    if getattr(opts, "disable_jwt_plugin", False):
        raise _invalid_metadata(
            "backchannel_logout_uri requires the jwt plugin (disableJwtPlugin must be false)"
        )
    try:
        parsed = urlsplit(uri)
        has_userinfo = bool(parsed.username or parsed.password)
        host = parsed.hostname or ""
    except ValueError:
        raise _invalid_metadata("backchannel_logout_uri must be an absolute URL") from None
    if not parsed.scheme or not parsed.netloc:
        raise _invalid_metadata("backchannel_logout_uri must be an absolute URL")
    if "#" in uri:
        raise _invalid_metadata("backchannel_logout_uri must not include a fragment component")
    if parsed.scheme.lower() != "https":
        raise _invalid_metadata("backchannel_logout_uri must use https")
    if has_userinfo:
        raise _invalid_metadata("backchannel_logout_uri must not contain credentials")
    if not is_public_routable_host(host):
        raise _invalid_metadata(
            "backchannel_logout_uri must not point to a private or reserved address"
        )


# --- protected registration (utils/initial-access-token.ts) --------------------------


def _bearer_error(status: int, error: str, description: str) -> OAuthError:
    return OAuthError(
        status,
        error,
        description,
        headers=[("WWW-Authenticate", f'Bearer error="{error}"'), *NO_STORE_HEADERS],
    )


async def authorize_initial_access_token(
    ctx: Ctx, opts: Any, client_metadata: dict[str, Any]
) -> dict[str, Any] | None:
    """TS ``authorizeInitialAccessToken``: ``None`` without Bearer credentials, else the
    ``validate_initial_access_token`` result; a malformed header, a missing validator or a
    rejected token fail closed with an RFC 6750 challenge."""
    authorization = (ctx.request.headers.get("authorization") or "").strip()
    parts = authorization.split()
    if not parts or parts[0].lower() != "bearer":
        return None
    if len(parts) != 2:
        raise _bearer_error(
            400, "invalid_request", "Malformed initial access token Authorization header"
        )
    validator = getattr(opts, "validate_initial_access_token", None)
    if validator is None:
        raise _bearer_error(401, "invalid_token", "Invalid initial access token")
    try:
        result = await _maybe_await(
            validator(
                {
                    "initialAccessToken": parts[1],
                    "headers": ctx.request.headers,
                    "clientMetadata": client_metadata,
                }
            )
        )
    except (APIError, OAuthError):
        raise
    except Exception:
        raise OAuthError(500, "server_error", "Initial access token validation failed") from None
    if not result and result != {}:
        raise _bearer_error(401, "invalid_token", "Invalid initial access token")
    return dict(result)


# --- creation chokepoint (register.ts:760 persistOAuthClientRegistration) -------------


async def _resolve_registration_resources(ctx: Ctx, opts: Any, requested: list[str]) -> list[str]:
    """TS ``resolveClientRegistrationResources``: defaults plus explicitly requested
    resources from the allowlist, each an existing enabled ``oauthResource``."""
    defaults = list(getattr(opts, "client_registration_default_resources", None) or [])
    allowed = {*defaults, *(getattr(opts, "client_registration_allowed_resources", None) or [])}
    for identifier in requested:
        if identifier not in allowed:
            raise OAuthError(
                400,
                "invalid_target",
                f"requested resource {identifier} is not allowed for client registration",
            )
    resources = list(dict.fromkeys([*defaults, *requested]))
    for identifier in resources:
        row = await get_resource(ctx, opts, identifier)
        if not row:
            raise OAuthError(
                400, "invalid_target", f"requested resource {identifier} does not exist"
            )
        if row.get("disabled"):
            raise OAuthError(400, "invalid_target", f"requested resource {identifier} is disabled")
    return resources


async def persist_client_registration(
    ctx: Ctx,
    opts: Any,
    *,
    metadata: dict[str, Any],
    source: str,
    user_id: str | None = None,
    reference_id: str | None = None,
    requested_resources: list[str] | None = None,
    client_credentials_scopes: list[str] | None = None,
) -> dict[str, Any]:
    """Create one client registration, TS ``persistOAuthClientRegistration``. ``source`` is
    ``"dynamic"`` (DCR) or ``"managed"`` (create-client). Returns the wire response body."""
    if source == "dynamic" and not metadata.get("scope"):
        default_scopes = getattr(opts, "client_registration_default_scopes", None) or getattr(
            opts, "scopes", None
        )
        metadata = {**metadata, "scope": " ".join(default_scopes or [])}
    body = apply_registration_defaults(metadata)
    auth_method = body["token_endpoint_auth_method"]
    is_public = auth_method == "none"
    await check_oauth_client(body, opts, source, ctx)

    client_id = generate_client_id(opts)
    client_secret = (
        None if is_public or auth_method == "private_key_jwt" else (generate_client_secret(opts))
    )
    stored_secret = (
        await store_client_secret(opts, client_secret, resolve_ctx_secret_config(ctx))
        if client_secret
        else None
    )
    # Confidential DCR clients may skip PKCE when the server opts out (register.ts:815, a8200b297).
    require_pkce = body.get("require_pkce")
    if (
        require_pkce is None
        and source == "dynamic"
        and not is_public
        and getattr(opts, "client_registration_require_pkce", True) is False
    ):
        require_pkce = False

    iat = int(utcnow().timestamp())
    expiration = getattr(opts, "client_registration_client_secret_expiration", None)
    if stored_secret:
        secret_expires_at = to_exp_jwt(expiration, iat) if source == "dynamic" and expiration else 0
    else:
        secret_expires_at = None
    effective = dict(body)
    if source == "dynamic":
        # The stored capability set is the registration scope policy, not the request
        # (register.ts:826).
        effective["scope"] = " ".join(resolve_registration_scopes(opts))
    effective.pop("resources", None)
    schema = oauth_to_schema(
        {
            **effective,
            "redirect_uris": body.get("redirect_uris") or [],
            "disabled": None,
            "client_secret_expires_at": secret_expires_at,
            "client_id": client_id,
            "client_secret": stored_secret,
            "client_id_issued_at": iat,
            "require_pkce": require_pkce,
            "user_id": None if reference_id else user_id,
            "reference_id": reference_id,
        }
    )
    schema["clientCredentialsScopes"] = client_credentials_scopes or []
    resources = await _resolve_registration_resources(
        ctx, opts, (requested_resources or []) if source == "dynamic" else []
    )
    created_at = _epoch_to_dt(iat)

    async def persist(adapter: Any) -> dict[str, Any]:
        client = await adapter.create(
            "oauthClient", {**schema, "createdAt": created_at, "updatedAt": created_at}
        )
        linked = (
            {
                link["resourceId"]
                for link in await adapter.find_many(
                    "oauthClientResource", [Where("clientId", client_id)]
                )
            }
            if resources
            else set()
        )
        now = utcnow()
        for resource_id in resources:
            if resource_id not in linked:
                await adapter.create(
                    "oauthClientResource",
                    {"clientId": client_id, "resourceId": resource_id, "createdAt": now},
                )
        return client

    client = await ctx.adapter.transaction(persist)
    response = schema_to_oauth(
        {
            **client,
            "clientSecret": apply_client_secret_prefix(opts, client_secret)
            if client_secret
            else None,
        }
    )
    if resources:
        response["resources"] = resources
    return response


def _created(body: dict[str, Any]) -> AuthResponse:
    return AuthResponse(status=201, body=body, headers=list(NO_STORE_HEADERS))


async def create_client_endpoint(ctx: Ctx, opts: Any, *, admin: bool = False) -> AuthResponse:
    """``/oauth2/create-client`` and SERVER_ONLY ``/admin/oauth2/create-client``, TS
    ``createOAuthClientEndpoint`` (register.ts:1204). The admin variant accepts server-owned
    fields and a ``client_credentials_scopes`` ceiling."""
    body = clean_client_body(ctx.body(), variant="admin" if admin else "create")
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "create")
    assert session is not None
    client_reference = getattr(opts, "client_reference", None)
    reference_id = await _maybe_await(client_reference(session)) if client_reference else None
    raw_scopes = body.pop("client_credentials_scopes", None) or []
    client_credentials_scopes = normalize_client_credentials_scopes(raw_scopes) if admin else []
    validate_client_credentials_scopes(
        client_credentials_scopes,
        resolve_registration_grant_types(body),
        body.get("token_endpoint_auth_method"),
        opts,
    )
    if client_credentials_scopes:
        await assert_client_privileges(ctx, session, opts, "configure-client-credentials-scopes")
    response = await persist_client_registration(
        ctx,
        opts,
        metadata=body,
        source="managed",
        user_id=None if reference_id else session["session"]["userId"],
        reference_id=reference_id,
        client_credentials_scopes=client_credentials_scopes,
    )
    if admin:
        response["client_credentials_scopes"] = list(client_credentials_scopes)
    return _created(response)


async def register_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /oauth2/register, RFC 7591 Dynamic Client Registration (TS ``registerEndpoint``).
    Authorized by a session, an RFC 7591 initial access token, or open registration."""
    body = clean_client_body(ctx.body(), variant="register")
    validate_registration_body(body)
    if not getattr(opts, "allow_dynamic_client_registration", False):
        raise OAuthError(403, "access_denied", "Client registration is disabled")

    session = await ctx.get_session()
    token_authorization = None if session else await authorize_initial_access_token(ctx, opts, body)
    if not (
        session
        or token_authorization is not None
        or getattr(opts, "allow_unauthenticated_client_registration", False)
    ):
        # RFC 6750 §3.1: no credentials get a bare challenge without an error code.
        return AuthResponse(
            status=401,
            body={"error_description": "Authentication required for client registration"},
            headers=[("WWW-Authenticate", "Bearer"), *NO_STORE_HEADERS],
        )
    anonymous = not session and token_authorization is None
    if anonymous and "client_credentials" in (body.get("grant_types") or []):
        raise _invalid_metadata("client_credentials grant requires authenticated registration")

    requested_resources = [r for r in body.pop("resources", None) or [] if isinstance(r, str) and r]
    if session:
        await assert_client_privileges(ctx, session, opts, "create")
    reference_id = (token_authorization or {}).get("referenceId")
    if reference_id is None and session:
        client_reference = getattr(opts, "client_reference", None)
        if client_reference is not None:
            reference_id = await _maybe_await(client_reference(session))
    response = await persist_client_registration(
        ctx,
        opts,
        metadata=body,
        source="dynamic",
        user_id=None if reference_id or not session else session["session"]["userId"],
        reference_id=reference_id,
        requested_resources=requested_resources,
    )
    return _created(response)
