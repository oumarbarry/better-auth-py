"""POST /oauth2/consent — record consent and re-enter the authorization flow.

Port of TS ``packages/oauth-provider/src/consent.ts`` (v1.6.23). Reads the stashed
(signed, before-hook-verified) ``oauth_query``; requested scopes must be a subset of the
originally requested set; ``accept !== true`` (strict) denies with an ``access_denied``
redirect. On accept it re-checks the ``login`` prompt against ``ba_iat``, upserts the
``oauthConsent`` row, and re-enters ``/oauth2/authorize`` with the ``consent`` (and any
satisfied ``login``) prompt removed and the server-minted ``ba_pl`` marker propagated.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .authorize import get_issuer, get_oauth_state
from .signed_query import parse_query
from .utils import (
    OAuthError,
    format_error_url,
    normalize_timestamp_value,
    parse_prompt,
    remove_prompt_from_query,
    search_params_to_query,
)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _session_satisfies_login_prompt(session_created_at: Any, issued_at: datetime | None) -> bool:
    """``login`` prompt is satisfied only when the session was created at/after the signed
    query's ``ba_iat`` — TS ``sessionSatisfiesLoginPrompt`` (consent.ts:159)."""
    if issued_at is None:
        return False
    normalized = normalize_timestamp_value(session_created_at)
    if normalized is None:
        return False
    return normalized.timestamp() >= issued_at.timestamp()


async def consent_endpoint(ctx: Ctx, opts: Any, authorize: Any) -> Any:
    state = get_oauth_state(ctx)
    stashed = state.get("query") if state else None
    if not stashed:
        raise OAuthError(400, "invalid_request", "missing oauth query")

    pairs = parse_query(stashed)

    def get(key: str) -> str | None:
        return next((v for k, v in pairs if k == key), None)

    scope_val = get("scope")
    original_requested_scopes = scope_val.split(" ") if scope_val is not None else []
    client_id = get("client_id")
    if not client_id:
        raise OAuthError(400, "invalid_client", "client_id is required")

    body = ctx.body()
    requested_raw = body.get("scope")
    requested_scopes = requested_raw.split(" ") if isinstance(requested_raw, str) else None
    if requested_scopes is not None and not all(
        sc in original_requested_scopes for sc in requested_scopes
    ):
        raise OAuthError(400, "invalid_request", "Scope not originally requested")

    # Strict boolean true.
    if body.get("accept") is not True:
        return AuthResponse(
            body={
                "redirect": True,
                "url": format_error_url(
                    get("redirect_uri") or "",
                    "access_denied",
                    "User denied access",
                    get("state"),
                    get_issuer(ctx, opts),
                ),
            }
        )

    session = await ctx.get_session()
    if session is None:
        raise APIError(401, "UNAUTHORIZED", "Not authenticated")

    prompt_set = parse_prompt(get("prompt") or "")
    has_login_prompt = "login" in prompt_set
    has_satisfied_login = has_login_prompt and _session_satisfies_login_prompt(
        session["session"].get("createdAt"), state.get("signed_query_issued_at") if state else None
    )
    if has_login_prompt and not has_satisfied_login:
        ctx.request.headers["accept"] = "application/json"
        return await authorize(ctx, search_params_to_query(pairs), {})

    reference_id = None
    post_login = getattr(opts, "post_login", None)
    if post_login and post_login.get("consentReferenceId"):
        reference_id = await _maybe_await(
            post_login["consentReferenceId"](
                {
                    "user": session["user"],
                    "session": session["session"],
                    "scopes": requested_scopes or original_requested_scopes,
                }
            )
        )

    scopes = requested_scopes or original_requested_scopes
    where = [Where("clientId", client_id), Where("userId", session["user"]["id"])]
    if reference_id:
        where.append(Where("referenceId", reference_id))
    found = await ctx.adapter.find_one("oauthConsent", where)

    now = datetime.fromtimestamp(int(utcnow().timestamp()), tz=timezone.utc)
    if found and found.get("id"):
        await ctx.adapter.update(
            "oauthConsent", [Where("id", found["id"])], {"scopes": scopes, "updatedAt": now}
        )
    else:
        await ctx.adapter.create(
            "oauthConsent",
            {
                "clientId": client_id,
                "userId": session["user"]["id"],
                "scopes": scopes,
                "referenceId": reference_id,
                "createdAt": now,
                "updatedAt": now,
            },
        )

    if requested_scopes is not None:
        pairs = [(k, v) for k, v in pairs if k != "scope"] + [("scope", " ".join(scopes))]

    ctx.request.headers["accept"] = "application/json"
    authorization_query = remove_prompt_from_query(pairs, "consent")
    if has_satisfied_login:
        authorization_query = remove_prompt_from_query(authorization_query, "login")
    post_login_cleared = (
        state is not None
        and state.get("post_login_cleared_for_session") is not None
        and state.get("post_login_cleared_for_session") == session["session"]["id"]
    )
    return await authorize(
        ctx, search_params_to_query(authorization_query), {"postLogin": post_login_cleared}
    )
