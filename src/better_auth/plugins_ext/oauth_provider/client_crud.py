"""Client CRUD + DCR endpoints.

Port of TS ``packages/oauth-provider/src/oauthClient/`` (v1.6.23). Every mutation routes
through :func:`assert_client_privileges`; ``cachedTrustedClients`` are immutable via CRUD;
``client_secret`` is never returned by get/list/update/rotate.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .register import (
    assert_client_privileges,
    check_oauth_client,
    clean_client_body,
    create_oauth_client,
    oauth_to_schema,
    schema_to_oauth,
)
from .utils import (
    OAuthError,
    apply_client_secret_prefix,
    generate_client_secret,
    store_client_secret,
    verify_oauth_query_params,
)

# Update allowlists: token_endpoint_auth_method (flips isPublic) and client_secret are
# immutable, so they are absent here — mirrors the TS update body schemas.
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
    "grant_types",
    "response_types",
    "type",
)
_ADMIN_UPDATE_FIELDS = (
    *_UPDATE_FIELDS,
    "client_secret_expires_at",
    "skip_consent",
    "enable_end_session",
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


async def create_client_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /oauth2/create-client (session)."""
    body = clean_client_body(ctx.body(), variant="create")
    session = await ctx.get_session()
    return await create_oauth_client(ctx, opts, is_register=False, body=body, session=session)


async def admin_create_client_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /admin/oauth2/create-client (SERVER_ONLY)."""
    body = clean_client_body(ctx.body(), variant="admin")
    session = await ctx.get_session()
    return await create_oauth_client(ctx, opts, is_register=False, body=body, session=session)


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
    stashes ``oauth_query`` into request state is Phase B; only the gate lives here."""
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


async def update_client_endpoint(ctx: Ctx, opts: Any, *, admin: bool = False) -> dict[str, Any]:
    """POST /oauth2/update-client (owner) / PATCH /admin/oauth2/update-client (SERVER_ONLY)."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "update")
    assert session is not None
    body = ctx.body()
    client_id = body["client_id"]
    _reject_trusted(opts, client_id)
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise _not_found()
    await _assert_ownership(ctx, opts, session, client)

    allowed = _ADMIN_UPDATE_FIELDS if admin else _UPDATE_FIELDS
    updates = {k: v for k, v in (body.get("update") or {}).items() if k in allowed}
    if not updates:
        return _strip_secret(client)

    check_oauth_client({**schema_to_oauth(client), **updates}, opts)
    updated = await ctx.adapter.update(
        "oauthClient",
        [Where("clientId", client_id)],
        {**oauth_to_schema(updates), "updatedAt": _updated_at_now()},
    )
    if not updated:
        raise OAuthError(500, "invalid_client", "unable to update client")
    return _strip_secret(updated)


async def rotate_client_secret_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    """POST /oauth2/client/rotate-secret (owner) — confidential clients only, returns the new
    prefixed secret."""
    session = await ctx.get_session()
    await assert_client_privileges(ctx, session, opts, "rotate")
    assert session is not None
    client_id = ctx.body()["client_id"]
    _reject_trusted(opts, client_id)
    client = await get_client(ctx, opts, client_id)
    if not client:
        raise _not_found()
    await _assert_ownership(ctx, opts, session, client)

    if client.get("public") or not client.get("clientSecret"):
        raise OAuthError(400, "invalid_client", "public clients cannot be updated")

    client_secret = generate_client_secret(opts)
    stored_secret = await store_client_secret(opts, client_secret)
    updated = await ctx.adapter.update(
        "oauthClient",
        [Where("clientId", client_id)],
        {"clientSecret": stored_secret, "updatedAt": _updated_at_now()},
    )
    if not updated:
        raise OAuthError(500, "invalid_client", "unable to update client")
    return schema_to_oauth(
        {**updated, "clientSecret": apply_client_secret_prefix(opts, client_secret)}
    )


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
