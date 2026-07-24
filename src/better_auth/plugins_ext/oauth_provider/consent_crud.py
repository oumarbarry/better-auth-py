"""Consent CRUD endpoints — 4 owner-scoped operations over ``oauthConsent``.

Port of TS ``packages/oauth-provider/src/oauthConsent/endpoints.ts`` (v1.6.23). All require
a session; get/update/delete are owner-only (``consent.userId === session.user.id``); update
narrows to scopes the client is allowed. Cross-user access is rejected with a bare
``UNAUTHORIZED`` (no OAuth ``error`` field, per the error-envelope reconciliation).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import APIError, Ctx
from .client_crud import get_client
from .utils import OAuthError


async def _require_session(ctx: Ctx) -> dict[str, Any]:
    session = await ctx.get_session()
    if session is None:
        raise APIError(401, "UNAUTHORIZED", "Not authenticated")
    return session


async def _get_consent(ctx: Ctx, consent_id: str) -> dict[str, Any] | None:
    return await ctx.adapter.find_one("oauthConsent", [Where("id", consent_id)])


async def get_consent_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    session = await _require_session(ctx)
    consent_id = ctx.request.query.get("id")
    if not consent_id:
        raise OAuthError(404, "not_found", "missing id parameter")
    consent = await _get_consent(ctx, consent_id)
    if not consent:
        raise OAuthError(404, "not_found", "no consent")
    if consent.get("userId") != session["user"]["id"]:
        raise APIError(401, "UNAUTHORIZED", "Not authorized")
    return consent


async def get_consents_endpoint(ctx: Ctx, opts: Any) -> list[dict[str, Any]]:
    session = await _require_session(ctx)
    return await ctx.adapter.find_many(
        "oauthConsent", [Where("userId", session["user"]["id"])]
    )


async def delete_consent_endpoint(ctx: Ctx, opts: Any) -> None:
    session = await _require_session(ctx)
    consent_id = ctx.body().get("id")
    if not consent_id:
        raise OAuthError(404, "not_found", "missing id parameter")
    consent = await _get_consent(ctx, consent_id)
    if not consent:
        raise OAuthError(404, "not_found", "no consent")
    if consent.get("userId") != session["user"]["id"]:
        raise APIError(401, "UNAUTHORIZED", "Not authorized")
    await ctx.adapter.delete("oauthConsent", [Where("id", consent_id)])


async def update_consent_endpoint(ctx: Ctx, opts: Any) -> dict[str, Any]:
    session = await _require_session(ctx)
    body = ctx.body()
    consent_id = body.get("id")
    if not consent_id:
        raise OAuthError(404, "not_found", "missing id parameter")
    consent = await _get_consent(ctx, consent_id)
    if not consent:
        raise OAuthError(404, "not_found", "no consent")
    if consent.get("userId") != session["user"]["id"]:
        raise APIError(401, "UNAUTHORIZED", "Not authorized")

    client = await get_client(ctx, opts, consent["clientId"])
    if not client:
        raise OAuthError(404, "not_found", "client not found")

    allowed_scopes = client.get("scopes") or getattr(opts, "scopes", None) or []
    updates = dict(body.get("update") or {})
    scopes = updates.get("scopes")
    if scopes is not None and not all(sc in allowed_scopes for sc in scopes):
        raise OAuthError(
            400,
            "invalid_request",
            f"unable to provide scopes to {client.get('referenceId') or client.get('userId')}",
        )

    now = datetime.fromtimestamp(int(utcnow().timestamp()), tz=timezone.utc)
    return await ctx.adapter.update(
        "oauthConsent", [Where("id", consent_id)], {**updates, "updatedAt": now}
    )
