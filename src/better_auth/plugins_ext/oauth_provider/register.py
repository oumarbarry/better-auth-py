"""Client registration: RFC 7591 wire <-> DB mapping, DCR validation, the single client
creation chokepoint, and the ``clientPrivileges`` gate.

Port of TS ``packages/oauth-provider/src/register.ts`` and ``oauthClient/privileges.ts``
(v1.6.23). The port has no zod body layer, so per-endpoint input allowlists here reproduce
what the TS route schemas strip (SERVER_ONLY fields, ``skip_consent`` on DCR).
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .utils import (
    OAuthError,
    apply_client_secret_prefix,
    generate_client_id,
    generate_client_secret,
    is_safe_url,
    parse_client_metadata,
    resolve_ctx_secret_config,
    store_client_secret,
)

DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"]

# --- input allowlists (replace the zod body schemas) ---------------------------------

#: Fields any session-authenticated create/DCR client may set (RFC 7591 public metadata).
_PUBLIC_CLIENT_FIELDS = (
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
    "token_endpoint_auth_method",
    "grant_types",
    "response_types",
    "type",
)
#: DCR additionally allows subject_type (checkOAuthClient validates it); create-client does not.
_REGISTER_FIELDS = (*_PUBLIC_CLIENT_FIELDS, "subject_type")
#: SERVER_ONLY admin fields.
_ADMIN_FIELDS = (
    *_PUBLIC_CLIENT_FIELDS,
    "client_secret_expires_at",
    "skip_consent",
    "enable_end_session",
    "require_pkce",
    "subject_type",
    "metadata",
)

_DEFAULTS = {
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
}


def clean_client_body(
    body: dict[str, Any], *, variant: str, apply_defaults: bool = True
) -> dict[str, Any]:
    """Allowlist a client body per endpoint variant and apply the route defaults, mirroring
    the TS zod schemas (unknown keys stripped)."""
    if variant == "register":
        allowed: tuple[str, ...] = _REGISTER_FIELDS
        if "skip_consent" in body:
            raise OAuthError(
                400,
                "invalid_client_metadata",
                "skip_consent cannot be set during dynamic client registration",
            )
    elif variant == "admin":
        allowed = _ADMIN_FIELDS
    else:  # "create"
        allowed = _PUBLIC_CLIENT_FIELDS
    cleaned = {k: v for k, v in body.items() if k in allowed}
    if apply_defaults:
        for key, default in _DEFAULTS.items():
            if cleaned.get(key) is None:
                cleaned[key] = default
    return cleaned


# --- clientPrivileges gate (oauthClient/privileges.ts) -------------------------------


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def assert_client_privileges(
    ctx: Ctx, session: dict[str, Any] | None, opts: Any, action: str
) -> None:
    """The single authorization helper for every client mutation — TS
    ``assertClientPrivileges``. UNAUTHORIZED without a session, BAD_REQUEST without headers,
    else consults ``client_privileges`` and rejects on a falsy result."""
    if session is None:
        raise APIError(401, "UNAUTHORIZED", "Not authenticated")
    if not ctx.request.headers:
        raise APIError(400, "BAD_REQUEST")
    client_privileges = getattr(opts, "client_privileges", None)
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


# --- wire <-> DB mapping (register.ts:302/407) ---------------------------------------

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
    "software_id": "softwareId",
    "software_version": "softwareVersion",
    "software_statement": "softwareStatement",
    "redirect_uris": "redirectUris",
    "post_logout_redirect_uris": "postLogoutRedirectUris",
    "token_endpoint_auth_method": "tokenEndpointAuthMethod",
    "grant_types": "grantTypes",
    "response_types": "responseTypes",
    "type": "type",
    "disabled": "disabled",
    "skip_consent": "skipConsent",
    "enable_end_session": "enableEndSession",
    "require_pkce": "requirePKCE",
    "subject_type": "subjectType",
    "reference_id": "referenceId",
    "public": "public",
}
_KNOWN_WIRE_KEYS = set(_WIRE_TO_SCHEMA) | {
    "scope",
    "client_secret_expires_at",
    "client_id_issued_at",
    "jwks",
    "jwks_uri",
    "metadata",
}


def _epoch_to_dt(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def oauth_to_schema(inp: dict[str, Any]) -> dict[str, Any]:
    """RFC 7591 wire shape -> DB ``SchemaClient`` — TS ``oauthToSchema``. Unknown wire keys
    collapse into the ``metadata`` JSON column (JSON-stringified). ``None`` values are omitted
    (TS undefined is ignored by the adapter, so an update never nulls an untouched column)."""
    rest = {k: v for k, v in inp.items() if k not in _KNOWN_WIRE_KEYS}
    meta_in = inp.get("metadata")
    meta_obj = {**rest, **(meta_in if isinstance(meta_in, dict) else {})}
    metadata = json.dumps(meta_obj, separators=(",", ":")) if meta_obj else None

    out: dict[str, Any] = {}
    for wire_key, schema_key in _WIRE_TO_SCHEMA.items():
        if wire_key in inp:
            out[schema_key] = inp[wire_key]

    scope = inp.get("scope")
    if scope is not None:
        out["scopes"] = scope.split(" ") if scope else None

    expires_at = inp.get("client_secret_expires_at")
    if expires_at:  # 0/None -> omit (never-expires stays unset); value is epoch seconds
        out["expiresAt"] = _epoch_to_dt(expires_at)
    created_at = inp.get("client_id_issued_at")
    if created_at:
        out["createdAt"] = _epoch_to_dt(created_at)

    out["metadata"] = metadata
    return {k: v for k, v in out.items() if v is not None}


def schema_to_oauth(row: dict[str, Any]) -> dict[str, Any]:
    """DB ``SchemaClient`` -> RFC 7591 wire shape — TS ``schemaToOAuth``. ``metadata`` is
    parsed and spread first; ``client_secret`` is included only if present (callers null it)."""
    out: dict[str, Any] = dict(parse_client_metadata(row.get("metadata")) or {})

    def put(key: str, value: Any) -> None:
        if value is not None:
            out[key] = value

    client_secret = row.get("clientSecret")
    put("client_id", row.get("clientId"))
    put("client_secret", client_secret)
    expires_at = row.get("expiresAt")
    _exp = round(expires_at.timestamp()) if isinstance(expires_at, datetime) else None
    if client_secret is not None:
        out["client_secret_expires_at"] = _exp if _exp is not None else 0
    scopes = row.get("scopes")
    put("scope", " ".join(scopes) if scopes else None)
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
    put("software_id", row.get("softwareId"))
    put("software_version", row.get("softwareVersion"))
    put("software_statement", row.get("softwareStatement"))
    out["redirect_uris"] = row.get("redirectUris") or []
    put("post_logout_redirect_uris", row.get("postLogoutRedirectUris"))
    put("token_endpoint_auth_method", row.get("tokenEndpointAuthMethod"))
    put("grant_types", row.get("grantTypes"))
    put("response_types", row.get("responseTypes"))
    put("public", row.get("public"))
    put("type", row.get("type"))
    put("disabled", row.get("disabled"))
    put("skip_consent", row.get("skipConsent"))
    put("enable_end_session", row.get("enableEndSession"))
    put("require_pkce", row.get("requirePKCE"))
    put("subject_type", row.get("subjectType"))
    put("reference_id", row.get("referenceId"))
    return out


# --- DCR validation (register.ts:77 checkOAuthClient) --------------------------------


def check_oauth_client(client: dict[str, Any], opts: Any, is_register: bool = False) -> None:
    """Validate a client-metadata combination — TS ``checkOAuthClient``. Raises
    :class:`OAuthError` (OAuth-shaped) on any violation."""
    is_public = client.get("token_endpoint_auth_method") == "none"

    ctype = client.get("type")
    if ctype:
        if is_public and ctype not in ("native", "user-agent-based"):
            raise OAuthError(
                400,
                "invalid_client_metadata",
                "Type must be 'native' or 'user-agent-based' for public applications",
            )
        if not is_public and ctype != "web":
            raise OAuthError(
                400, "invalid_client_metadata", "Type must be 'web' for confidential applications"
            )

    grant_types = client.get("grant_types") or ["authorization_code"]
    redirect_uris = client.get("redirect_uris") or []
    if "authorization_code" in grant_types and not redirect_uris:
        raise OAuthError(
            400,
            "invalid_redirect_uri",
            "Redirect URIs are required for authorization_code and implicit grant types",
        )
    for uri in redirect_uris:
        if not is_safe_url(uri):
            raise OAuthError(400, "invalid_redirect_uri", f"invalid redirect_uri {uri}")
    for uri in client.get("post_logout_redirect_uris") or []:
        if not is_safe_url(uri):
            raise OAuthError(400, "invalid_redirect_uri", f"invalid post_logout_redirect_uri {uri}")

    response_types = client.get("response_types") or ["code"]
    if "authorization_code" in grant_types and "code" not in response_types:
        raise OAuthError(
            400,
            "invalid_client_metadata",
            "When 'authorization_code' grant type is used, 'code' response type must be included",
        )

    subject_type = client.get("subject_type")
    if subject_type is not None:
        if subject_type not in ("public", "pairwise"):
            raise OAuthError(
                400, "invalid_client_metadata", 'subject_type must be "public" or "pairwise"'
            )
        if subject_type == "pairwise" and not getattr(opts, "pairwise_secret", None):
            raise OAuthError(
                400,
                "invalid_client_metadata",
                "pairwise subject_type requires server pairwiseSecret configuration",
            )
        if subject_type == "pairwise" and len(redirect_uris) > 1:
            hosts = {urlsplit(u).netloc for u in redirect_uris}
            if len(hosts) > 1:
                raise OAuthError(
                    400,
                    "invalid_client_metadata",
                    "pairwise clients with redirect_uris on different hosts require a "
                    "sector_identifier_uri, which is not yet supported. All redirect_uris must "
                    "share the same host.",
                )

    scope = client.get("scope")
    requested = [s for s in (scope.split(" ") if scope else []) if s]
    if is_register:
        allowed = getattr(opts, "client_registration_allowed_scopes", None) or getattr(
            opts, "scopes", None
        )
    else:
        allowed = getattr(opts, "scopes", None)
    if allowed is not None:
        valid = set(allowed)
        for sc in requested:
            if sc not in valid:
                raise OAuthError(400, "invalid_scope", f"cannot request scope {sc}")

    if is_register and client.get("require_pkce") is False:
        raise OAuthError(
            400, "invalid_client_metadata", "pkce is required for registered clients."
        )


# --- unauthenticated DCR override (register.ts:15) -----------------------------------


def resolve_unauthenticated_auth(body: dict[str, Any]) -> dict[str, Any]:
    """Force ``token_endpoint_auth_method: none`` for anonymous DCR (RFC 7591 §3.2.1); clear
    ``type: web`` since it is confidential-only — TS ``resolveUnauthenticatedAuth``."""
    if body.get("token_endpoint_auth_method") == "none":
        return {"token_endpoint_auth_method": "none", "type": body.get("type")}
    return {
        "token_endpoint_auth_method": "none",
        "type": None if body.get("type") == "web" else body.get("type"),
    }


def _to_exp_seconds(expiration: Any, iat: int) -> int:
    """Client-secret expiry -> absolute epoch seconds. ponytail: accepts an int seconds
    offset only (TS ``toExpJWT`` also parses ``"30d"`` strings); widen if a duration-string
    config value is ever needed."""
    if isinstance(expiration, (int, float)):
        return iat + int(expiration)
    return 0


# --- creation chokepoint (register.ts:199) -------------------------------------------


async def create_oauth_client(
    ctx: Ctx,
    opts: Any,
    *,
    is_register: bool,
    body: dict[str, Any],
    session: dict[str, Any] | None,
) -> AuthResponse:
    """Single authorization chokepoint for OAuth client creation — TS
    ``createOAuthClientEndpoint``. ``create`` privileges are enforced here so no route reaches
    persistence without the gate; anonymous DCR (constrained to public clients upstream) is
    the only path that skips it."""
    if is_register:
        if session is not None:
            await assert_client_privileges(ctx, session, opts, "create")
    else:
        await assert_client_privileges(ctx, session, opts, "create")

    is_public = body.get("token_endpoint_auth_method") == "none"
    check_oauth_client(body, opts, is_register)

    client_id = generate_client_id(opts)
    client_secret = None if is_public else generate_client_secret(opts)
    stored_secret = (
        await store_client_secret(opts, client_secret, resolve_ctx_secret_config(ctx))
        if client_secret
        else None
    )

    iat = int(utcnow().timestamp())
    client_reference = getattr(opts, "client_reference", None)
    reference_id = None
    if client_reference is not None:
        reference_id = await _maybe_await(client_reference(session))

    expiration = getattr(opts, "client_registration_client_secret_expiration", None)
    if stored_secret:
        client_secret_expires_at = (
            _to_exp_seconds(expiration, iat) if (is_register and expiration) else 0
        )
    else:
        client_secret_expires_at = None

    session_user_id = session["session"]["userId"] if session else None
    schema = oauth_to_schema(
        {
            **body,
            "disabled": None,
            "client_secret_expires_at": client_secret_expires_at,
            "client_id": client_id,
            "client_secret": stored_secret,
            "client_id_issued_at": iat,
            "public": is_public,
            "user_id": None if reference_id else session_user_id,
            "reference_id": reference_id,
        }
    )
    created_at = _epoch_to_dt(iat)
    client = await ctx.adapter.create(
        "oauthClient", {**schema, "createdAt": created_at, "updatedAt": created_at}
    )

    response = schema_to_oauth(
        {
            **client,
            "clientSecret": apply_client_secret_prefix(opts, client_secret)
            if client_secret
            else None,
        }
    )
    return AuthResponse(
        status=201,
        body=response,
        headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
    )


async def register_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /oauth2/register — RFC 7591 Dynamic Client Registration (TS ``registerEndpoint``)."""
    if not getattr(opts, "allow_dynamic_client_registration", False):
        raise OAuthError(403, "access_denied", "Client registration is disabled")

    body = clean_client_body(ctx.body(), variant="register")
    session = await ctx.get_session()

    if not (session or getattr(opts, "allow_unauthenticated_client_registration", False)):
        raise OAuthError(401, "invalid_token", "Authentication required for client registration")

    if not session:
        if "client_credentials" in (body.get("grant_types") or []):
            raise OAuthError(
                400,
                "invalid_client_metadata",
                "client_credentials grant requires authenticated registration",
            )
        resolved = resolve_unauthenticated_auth(body)
        body["token_endpoint_auth_method"] = resolved["token_endpoint_auth_method"]
        if resolved["type"] is None:
            body.pop("type", None)
        else:
            body["type"] = resolved["type"]

    if not body.get("scope"):
        default_scopes = getattr(opts, "client_registration_default_scopes", None) or getattr(
            opts, "scopes", DEFAULT_SCOPES
        )
        body["scope"] = " ".join(default_scopes)

    return await create_oauth_client(ctx, opts, is_register=True, body=body, session=session)
