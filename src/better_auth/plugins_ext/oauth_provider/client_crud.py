"""Client CRUD endpoints.

Port of TS ``packages/oauth-provider/src/oauthClient/`` (v1.7.6). Every mutation routes
through :func:`assert_client_privileges`; ``cachedTrustedClients`` are immutable via CRUD;
``client_secret`` is never returned by get/list/update. Creation lives in ``register.py``.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .register import (
    NO_STORE_HEADERS,
    assert_client_privileges,
    check_oauth_client,
    normalize_client_credentials_scopes,
    oauth_to_schema,
    schema_to_oauth,
    validate_client_credentials_scopes,
)
from .utils import (
    OAuthError,
    apply_client_secret_prefix,
    generate_client_secret,
    resolve_ctx_secret_config,
    store_client_secret,
    verify_oauth_query_params,
)

# Update allowlists (oauthClient/index.ts:493/547): token_endpoint_auth_method and
# client_secret are immutable, so they are absent here.
_UPDATE_FIELDS = (
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
    "application_type",
    "grant_types",
    "response_types",
)
_ADMIN_UPDATE_FIELDS = (
    *_UPDATE_FIELDS,
    "client_credentials_scopes",
    "client_secret_expires_at",
    "skip_consent",
    "enable_end_session",
    "dpop_bound_access_tokens",
    "metadata",
)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _updated_at_now() -> datetime:
    # TS: new Date(Math.floor(Date.now()/1000)*1000) — second precision.
    return datetime.fromtimestamp(int(utcnow().timestamp()), tz=timezone.utc)


async def get_client(ctx: Ctx, opts: Any, client_id: str) -> dict[str, Any] | None:
    """Load a client by id. ponytail: TS keeps a module TTL cache of ``cachedTrustedClients``;
    the port reads the DB directly (a correctness-equivalent, cache-free lookup) — add the
    cache if client reads ever become hot."""
    return await ctx.adapter.find_one("oauthClient", [Where("clientId", client_id)])


def _not_found() -> OAuthError:
    return OAuthError(404, "not_found", "client not found")


async def _assert_ownership(
    ctx: Ctx, opts: Any, session: dict[str, Any], client: dict[str, Any]
) -> None:
    """TS ownership check: userId must match the session user; else referenceId via
    clientReference; else UNAUTHORIZED."""
    client_reference = getattr(opts, "client_reference", None)
    if client.get("userId"):
        if client["userId"] != session["user"]["id"]:
            raise APIError(401, "UNAUTHORIZED", "Not authorized")
    elif client.get("referenceId") and client_reference is not None:
        if client["referenceId"] != await _maybe_await(client_reference(session)):
            raise APIError(401, "UNAUTHORIZED", "Not authorized")
    else:
        raise APIError(401, "UNAUTHORIZED", "Not authorized")


def _reject_trusted(opts: Any, client_id: str) -> None:
    trusted = getattr(opts, "cached_trusted_clients", None)
    if trusted and client_id in trusted:
        raise OAuthError(500, "invalid_client", "trusted clients must be updated manually")


def _strip_secret(client: dict[str, Any]) -> dict[str, Any]:
    res = schema_to_oauth(client)
    res.pop("client_secret", None)
    res.pop("client_secret_expires_at", None)
    return res


# --- endpoints -----------------------------------------------------------------------


async def get_client_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    """GET /oauth2/get-client (owner) — strips client_secret."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "read")
    assert session is not None
    client_id = ctx.request.query.get("client_id")
    client = await get_client(ctx, opts, client_id) if client_id else None
    if not client:
        raise _not_found()
    await _assert_ownership(ctx, opts, session, client)
    return _strip_secret(client)


async def get_client_public_endpoint(ctx: Ctx, opts: Any, client_id: str) -> dict[str, Any]:
    """Public UI fields for a client (login-flow pages)."""
    client = await get_client(ctx, opts, client_id)
    if not client or client.get("disabled"):
        raise _not_found()
    return schema_to_oauth(
        {
            "clientId": client.get("clientId"),
            "name": client.get("name"),
            "uri": client.get("uri"),
            "contacts": client.get("contacts"),
            "icon": client.get("icon"),
            "tos": client.get("tos"),
            "policy": client.get("policy"),
        }
    )


async def get_client_public_prelogin_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    """POST /oauth2/public-client-prelogin — gated on allowPublicClientPrelogin + a valid
    signed ``oauth_query`` (TS ``publicSessionMiddleware``). ponytail: the before-hook that
    stashes ``oauth_query`` into request state is
    ``OAuthProviderPlugin._before_stash_oauth_query`` in ``__init__.py``; only the
    prelogin gate lives here."""
    if not getattr(opts, "allow_public_client_prelogin", False):
        raise APIError(400, "BAD_REQUEST")
    body = ctx.body()
    oauth_query = body.get("oauth_query") or ""
    if not verify_oauth_query_params(oauth_query, ctx.auth.secret):
        raise OAuthError(401, "invalid_signature", "invalid signature")
    return await get_client_public_endpoint(ctx, opts, body["client_id"])


async def get_clients_endpoint(ctx: Ctx, opts: Any) -> list[dict[str, Any]] | None:
    """GET /oauth2/get-clients — the caller's clients (by referenceId or userId)."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "list")
    assert session is not None
    client_reference = getattr(opts, "client_reference", None)
    reference_id = await _maybe_await(client_reference(session)) if client_reference else None
    if reference_id:
        where = [Where("referenceId", reference_id)]
    elif session["user"].get("id"):
        where = [Where("userId", session["user"]["id"])]
    else:
        raise APIError(400, "BAD_REQUEST", "either user_id or reference_id must be provided")
    rows = await ctx.adapter.find_many("oauthClient", where)
    return [_strip_secret(row) for row in rows]


async def _owns_client(
    ctx: Ctx, opts: Any, session: dict[str, Any], client: dict[str, Any]
) -> bool:
    if client.get("userId"):
        return client["userId"] == session["user"]["id"]
    client_reference = getattr(opts, "client_reference", None)
    if client.get("referenceId") and client_reference is not None:
        return client["referenceId"] == await _maybe_await(client_reference(session))
    return False


def _update_response(client: dict[str, Any], admin: bool) -> dict[str, Any]:
    res = _strip_secret(client)
    if admin:
        res["client_credentials_scopes"] = list(client.get("clientCredentialsScopes") or [])
    return res


async def update_client_endpoint(ctx: Ctx, opts: Any, *, admin: bool = False) -> dict[str, Any]:
    """POST /oauth2/update-client (owner) / PATCH /admin/oauth2/update-client (SERVER_ONLY),
    TS ``updateClientEndpoint`` (oauthClient/endpoints.ts:212). An admin may set another
    owner's ``client_credentials_scopes`` alone behind ``configure-client-credentials-scopes``."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "update")
    assert session is not None
    body = ctx.body()
    client_id = body["client_id"]
    _reject_trusted(opts, client_id)
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise _not_found()

    allowed = _ADMIN_UPDATE_FIELDS if admin else _UPDATE_FIELDS
    updates = {
        k: v for k, v in (body.get("update") or {}).items() if k in allowed and v is not None
    }
    raw_scopes = updates.pop("client_credentials_scopes", None)
    owns = await _owns_client(ctx, opts, session, client)
    cross_owner = not owns and admin and raw_scopes is not None and not updates
    if not owns and not cross_owner:
        raise APIError(401, "UNAUTHORIZED", "Not authorized")
    if cross_owner:
        await assert_client_privileges(ctx, session, opts, "configure-client-credentials-scopes")
    if not updates and raw_scopes is None:
        return _update_response(client, admin)

    final_grants = updates.get("grant_types") or client.get("grantTypes") or []
    final_method = updates.get("token_endpoint_auth_method") or client.get(
        "tokenEndpointAuthMethod"
    )
    scopes = None if raw_scopes is None else normalize_client_credentials_scopes(raw_scopes)
    if scopes is not None:
        validate_client_credentials_scopes(scopes, final_grants, final_method, opts)
        if scopes and not cross_owner:
            await assert_client_privileges(
                ctx, session, opts, "configure-client-credentials-scopes"
            )

    await check_oauth_client({**schema_to_oauth(client), **updates}, opts, ctx=ctx)
    schema_updates = oauth_to_schema(updates)
    if "client_credentials" not in final_grants or final_method == "none":
        schema_updates["clientCredentialsScopes"] = []
    elif scopes is not None:
        schema_updates["clientCredentialsScopes"] = scopes
    # Clear obsolete key material when the auth method changes; leaving private_key_jwt
    # issues a new secret (endpoints.ts:353, c7d22539e). The update allowlists keep
    # token_endpoint_auth_method immutable, as in TS, so this only guards direct callers.
    new_method = updates.get("token_endpoint_auth_method")
    if new_method == "private_key_jwt":
        schema_updates["clientSecret"] = None
    elif new_method:
        schema_updates["jwks"] = None
        schema_updates["jwksUri"] = None
        schema_updates["clientSecret"] = await store_client_secret(
            opts, generate_client_secret(opts), resolve_ctx_secret_config(ctx)
        )
    updated = await ctx.adapter.update(
        "oauthClient",
        [Where("clientId", client_id)],
        {**schema_updates, "updatedAt": _updated_at_now()},
    )
    if not updated:
        raise OAuthError(500, "invalid_client", "unable to update client")
    return _update_response(updated, admin)


async def rotate_client_secret_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /oauth2/client/rotate-secret (owner): confidential secret-based clients only,
    returns the new prefixed secret with ``no-store`` (TS endpoints.ts:397, 2196ea65e)."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "rotate")
    assert session is not None
    client_id = ctx.body()["client_id"]
    _reject_trusted(opts, client_id)
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise _not_found()
    await _assert_ownership(ctx, opts, session, client)

    if client.get("tokenEndpointAuthMethod") == "none" or not client.get("clientSecret"):
        raise OAuthError(
            400,
            "invalid_client",
            "secret rotation is only available for clients using client_secret authentication",
        )

    client_secret = generate_client_secret(opts)
    stored_secret = await store_client_secret(opts, client_secret, resolve_ctx_secret_config(ctx))
    updated = await ctx.adapter.update(
        "oauthClient",
        [Where("clientId", client_id)],
        {"clientSecret": stored_secret, "updatedAt": _updated_at_now()},
    )
    if not updated:
        raise OAuthError(500, "invalid_client", "unable to update client")
    body = schema_to_oauth(
        {**updated, "clientSecret": apply_client_secret_prefix(opts, client_secret)}
    )
    return AuthResponse(body=body, headers=list(NO_STORE_HEADERS))


async def delete_client_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /oauth2/delete-client (owner)."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "delete")
    assert session is not None
    client_id = ctx.body()["client_id"]
    _reject_trusted(opts, client_id)
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise _not_found()
    await _assert_ownership(ctx, opts, session, client)
    await ctx.adapter.delete("oauthClient", [Where("clientId", client_id)])
    return AuthResponse(status=200, body={"success": True})
