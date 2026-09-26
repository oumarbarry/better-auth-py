"""POST /oauth2/consent — record consent and re-enter the authorization flow.

Port of TS ``packages/oauth-provider/src/consent.ts`` (v1.7.6). Reads the stashed
(signed, before-hook-verified) ``oauth_query``; requested scopes and accepted
``claims.userinfo`` names must be subsets of the original request; ``accept !== true``
(strict) denies with an ``access_denied`` redirect. On accept it re-checks the ``login``
prompt against ``ba_iat``, upserts the ``oauthConsent`` row (scopes, UserInfo claims and
resources), and re-enters ``/oauth2/authorize`` with the ``consent`` (and any satisfied
``login`` and ``max_age``) prompt removed and the server-minted ``ba_pl`` marker propagated.
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from typing import Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .authorize import get_issuer, get_oauth_state
from .claims import (
    filter_claims_request_user_info_claims,
    get_requested_user_info_claims,
    get_supported_claims,
    is_claims_request_input,
    is_valid_oidc_claims_request,
)
from .signed_query import parse_query
from .utils import (
    OAuthError,
    format_error_url,
    is_session_fresh_for_signed_query,
    parse_prompt,
    remove_max_age_from_query,
    remove_prompt_from_query,
    search_params_to_query,
)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _set_param(pairs: list[tuple[str, str]], key: str, value: str) -> list[tuple[str, str]]:
    """``URLSearchParams.set``: replace the first occurrence in place, drop the others."""
    out: list[tuple[str, str]] = []
    placed = False
    for k, v in pairs:
        if k != key:
            out.append((k, v))
        elif not placed:
            out.append((key, value))
            placed = True
    if not placed:
        out.append((key, value))
    return out


async def consent_endpoint(ctx: Ctx, opts: Any, authorize: Any) -> Any:
    # Body schema ``claims: claimsRequestParameterSchema.optional()`` (oauth.ts:784).
    accepted_claims_request = ctx.body().get("claims")
    if accepted_claims_request is not None:
        if not is_claims_request_input(accepted_claims_request):
            raise APIError(400, "VALIDATION_ERROR", "[body.claims] Invalid input")
        if not is_valid_oidc_claims_request(accepted_claims_request):
            raise APIError(
                400,
                "VALIDATION_ERROR",
                "[body.claims] claims must be a valid Claims request object",
            )
    state = get_oauth_state(ctx)
    stashed = state.get("query") if state else None
    if not stashed:
        raise OAuthError(400, "invalid_request", "missing oauth query")

    pairs = parse_query(stashed)

    def get(key: str) -> str | None:
        return next((v for k, v in pairs if k == key), None)

    scope_val = get("scope")
    original_requested_scopes = scope_val.split(" ") if scope_val is not None else []
    supported_claims = get_supported_claims(opts)
    original_claims = get_requested_user_info_claims(get("claims"), supported_claims)
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
    # Accepted claims.userinfo names (consent.ts:59, e3125e872).
    accepted_claims = (
        get_requested_user_info_claims(accepted_claims_request, supported_claims)
        if accepted_claims_request is not None
        else original_claims
    )
    if accepted_claims_request is not None and not all(
        claim in original_claims for claim in accepted_claims
    ):
        raise OAuthError(400, "invalid_request", "Claim not originally requested")

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
    has_satisfied_login = has_login_prompt and is_session_fresh_for_signed_query(
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
    resources = [v for k, v in pairs if k == "resource"] or None
    if found and found.get("id"):
        await ctx.adapter.update(
            "oauthConsent",
            [Where("id", found["id"])],
            {
                "resources": resources,
                "scopes": scopes,
                "requestedUserInfoClaims": accepted_claims,
                "updatedAt": now,
            },
        )
    else:
        await ctx.adapter.create(
            "oauthConsent",
            {
                "clientId": client_id,
                "userId": session["user"]["id"],
                "scopes": scopes,
                "requestedUserInfoClaims": accepted_claims,
                "createdAt": now,
                "updatedAt": now,
                "resources": resources,
                "referenceId": reference_id,
            },
        )

    if requested_scopes is not None:
        pairs = _set_param(pairs, "scope", " ".join(scopes))
    if accepted_claims_request is not None:
        claims_request = filter_claims_request_user_info_claims(get("claims"), accepted_claims)
        if claims_request:
            serialized = json.dumps(claims_request, separators=(",", ":"), ensure_ascii=False)
            pairs = _set_param(pairs, "claims", serialized)
        else:
            pairs = [(k, v) for k, v in pairs if k != "claims"]

    ctx.request.headers["accept"] = "application/json"
    authorization_query = remove_prompt_from_query(pairs, "consent")
    if has_satisfied_login:
        authorization_query = remove_prompt_from_query(authorization_query, "login")
        authorization_query = remove_max_age_from_query(authorization_query)
    post_login_cleared = (
        state is not None
        and state.get("post_login_cleared_for_session") is not None
        and state.get("post_login_cleared_for_session") == session["session"]["id"]
    )
    return await authorize(
        ctx, search_params_to_query(authorization_query), {"postLogin": post_login_cleared}
    )
