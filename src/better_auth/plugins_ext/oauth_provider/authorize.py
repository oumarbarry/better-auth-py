"""GET /oauth2/authorize — the authorization-code flow + signed-query resume.

Port of TS ``packages/oauth-provider/src/authorize.ts`` (v1.6.23). The 10-step flow:
grant gate, PAR resolution, client validation, redirect_uri match (exact + RFC 8252 §7.3
loopback-IP port-agnostic), scope validation, PKCE enforcement, session/prompt gates
(signed login/consent page redirects or OIDC ``prompt=none`` error redirects), consent
lookup, and authorization-code minting into the verification store.

Request-scoped state (TS ``defineRequestState`` / ``oAuthState``) is stashed on the ``Ctx``
object, which the core dispatcher threads through before-hook -> endpoint -> after-hook.
"""

from __future__ import annotations

import inspect
import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...crypto import generate_random_string
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .metadata import _issuer
from .signed_query import Pairs
from .utils import (
    client_allows_grant,
    format_error_url,
    handle_redirect,
    is_loopback_ip,
    is_pkce_required,
    parse_prompt,
    sign_oauth_query,
    store_token,
)

# --- request-scoped state (TS oAuthState) --------------------------------------------

_STATE_ATTR = "_oauth_provider_state"

#: Code alphabet — TS ``generateRandomString(32, "a-z", "A-Z", "0-9")``.
_CODE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def set_oauth_state(ctx: Ctx, state: dict[str, Any] | None) -> None:
    setattr(ctx, _STATE_ATTR, state)


def get_oauth_state(ctx: Ctx) -> dict[str, Any] | None:
    return getattr(ctx, _STATE_ATTR, None)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def get_issuer(ctx: Ctx, opts: Any) -> str:
    """RFC 9207 issuer identifier — TS ``getIssuer`` (jwt-plugin issuer ?? baseURL, validated)."""
    return _issuer(ctx.auth, opts)


def _error_page(ctx: Ctx) -> str:
    cfg = getattr(ctx.auth, "on_api_error", None)
    return getattr(cfg, "error_url", None) or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"


def _get_error_url(ctx: Ctx, error: str, description: str) -> str:
    """Error page for pre-redirect_uri-validation failures — TS ``getErrorURL``."""
    return format_error_url(_error_page(ctx), error, description)


def serialize_authorization_query(query: dict[str, Any]) -> Pairs:
    """Flatten the authorization query into ordered pairs (skip ``None``) — TS
    ``serializeAuthorizationQuery``."""
    pairs: Pairs = []
    for key, value in query.items():
        if value is None:
            continue
        if isinstance(value, list):
            pairs.extend((key, str(item)) for item in value)
        else:
            pairs.append((key, str(value)))
    return pairs


def _redirect_with_code_url(redirect_uri: str, params: Pairs) -> str:
    """Apply ``URLSearchParams.set`` semantics (replace-then-append) to ``redirect_uri``."""
    parts = urlsplit(redirect_uri)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    set_keys = {k for k, _ in params}
    merged = [(k, v) for k, v in existing if k not in set_keys] + params
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged), parts.fragment))


# --- signed prompt-page redirects ----------------------------------------------------


def sign_params(
    ctx: Ctx,
    opts: Any,
    query: dict[str, Any],
    *,
    post_login_cleared_for_session: str | None = None,
) -> str:
    """Sign the authorization query for an app-hosted page redirect — TS ``signParams``."""
    issued_at = int(utcnow().timestamp() * 1000)
    iat = issued_at // 1000
    exp = iat + (opts.code_expires_in or 600)
    return sign_oauth_query(
        serialize_authorization_query(query),
        ctx.auth.secret,
        exp=exp,
        issued_at_ms=issued_at,
        post_login_cleared_for_session=post_login_cleared_for_session,
    )


def _redirect_with_prompt_code(
    ctx: Ctx,
    opts: Any,
    query: dict[str, Any],
    prompt_type: str,
    *,
    page: str | None = None,
    session_id: str | None = None,
) -> AuthResponse:
    """Redirect to the signed app-hosted page for ``prompt_type`` — TS ``redirectWithPromptCode``."""  # noqa: E501
    post_login = getattr(opts, "post_login", None)
    cleared = session_id if (prompt_type == "consent" and post_login) else None
    signed = sign_params(ctx, opts, query, post_login_cleared_for_session=cleared)

    path = opts.login_page
    if prompt_type == "select_account":
        path = (getattr(opts, "select_account", None) or {}).get("page") or opts.login_page
    elif prompt_type == "post_login":
        if not (post_login and post_login.get("page")):
            raise APIError(500, "INTERNAL_SERVER_ERROR", "postLogin should have been defined")
        path = post_login["page"]
    elif prompt_type == "consent":
        path = opts.consent_page
    elif prompt_type == "create":
        path = (getattr(opts, "signup", None) or {}).get("page") or opts.login_page
    return handle_redirect(ctx, f"{page or path}?{signed}")


def _redirect_prompt_none_error(
    ctx: Ctx, opts: Any, query: dict[str, Any], error: str, description: str
) -> AuthResponse:
    return handle_redirect(
        ctx,
        format_error_url(
            query["redirect_uri"], error, description, query.get("state"), get_issuer(ctx, opts)
        ),
    )


# --- authorization-code minting ------------------------------------------------------


async def redirect_with_authorization_code(
    ctx: Ctx,
    opts: Any,
    *,
    query: dict[str, Any],
    client_id: str,
    user_id: str,
    session_id: str,
    auth_time: int,
    reference_id: str | None,
) -> AuthResponse:
    """Mint an authorization code into the verification store and redirect — TS
    ``redirectWithAuthorizationCode``."""
    code = generate_random_string(32, _CODE_ALPHABET)
    iat = int(utcnow().timestamp())
    exp = iat + (opts.code_expires_in or 600)
    value = json.dumps(
        {
            "type": "authorization_code",
            "query": query,
            "userId": user_id,
            "sessionId": session_id,
            "referenceId": reference_id,
            "authTime": auth_time,
        },
        separators=(",", ":"),
    )
    from datetime import datetime, timezone

    await ctx.internal.create_verification_value(
        {
            "identifier": await store_token(opts.store_tokens, code, "authorization_code"),
            "value": value,
            "createdAt": datetime.fromtimestamp(iat, tz=timezone.utc),
            "updatedAt": datetime.fromtimestamp(iat, tz=timezone.utc),
            "expiresAt": datetime.fromtimestamp(exp, tz=timezone.utc),
        }
    )

    params: Pairs = [("code", code)]
    if query.get("state"):
        params.append(("state", query["state"]))
    params.append(("iss", get_issuer(ctx, opts)))
    return handle_redirect(ctx, _redirect_with_code_url(query["redirect_uri"], params))


# --- main endpoint -------------------------------------------------------------------


async def authorize_endpoint(
    ctx: Ctx, opts: Any, query: dict[str, Any], settings: dict[str, Any] | None = None
) -> AuthResponse:
    settings = settings or {}

    # 1. Grant gate.
    if opts.grant_types and "authorization_code" not in opts.grant_types:
        raise APIError(404, "NOT_FOUND")

    # 2. PAR (request_uri) resolution — RFC 9126 §4: only client_id carried from the URL.
    if query.get("request_uri"):
        resolver = getattr(opts, "request_uri_resolver", None)
        if resolver is None:
            return handle_redirect(
                ctx, _get_error_url(ctx, "invalid_request_uri", "request_uri not supported")
            )
        resolved = await _maybe_await(
            resolver(
                {
                    "requestUri": query["request_uri"],
                    "clientId": query.get("client_id") or "",
                    "ctx": ctx,
                }
            )
        )
        if not resolved:
            return handle_redirect(
                ctx, _get_error_url(ctx, "invalid_request_uri", "request_uri is invalid or expired")
            )
        url_client_id = query.get("client_id")
        query = dict(resolved)
        if url_client_id:
            query["client_id"] = url_client_id

    # ponytail: TS also stashes the resolved query in oAuthState here for the social
    # round-trip getOAuthState persistence; the port has no cross-request oAuthState store
    # (consent/continue read the same-request before-hook stash), so this is a no-op — skip.

    if not query.get("client_id"):
        return handle_redirect(ctx, _get_error_url(ctx, "invalid_client", "client_id is required"))
    if not query.get("response_type"):
        return handle_redirect(
            ctx, _get_error_url(ctx, "invalid_request", "response_type is required")
        )

    prompt_set = parse_prompt(query.get("prompt") or "")
    prompt_none = "none" in prompt_set
    select_account = getattr(opts, "select_account", None)
    if "select_account" in prompt_set and not (select_account and select_account.get("page")):
        return handle_redirect(
            ctx, _get_error_url(ctx, "unsupported_prompt_select_account", "unsupported prompt type")
        )
    if query.get("response_type") != "code":
        return handle_redirect(
            ctx, _get_error_url(ctx, "unsupported_response_type", "unsupported response type")
        )

    # 4. Client validation.
    from .client_crud import get_client

    client = await get_client(ctx, opts, query["client_id"])
    if not client:
        return handle_redirect(ctx, _get_error_url(ctx, "invalid_client", "client_id is required"))
    if client.get("disabled"):
        return handle_redirect(ctx, _get_error_url(ctx, "client_disabled", "client is disabled"))
    if not client_allows_grant(client, "authorization_code"):
        return handle_redirect(
            ctx,
            _get_error_url(
                ctx,
                "unauthorized_client",
                "client is not authorized to use the authorization_code grant",
            ),
        )

    # 5. redirect_uri match — exact string OR RFC 8252 §7.3 loopback-IP (port-agnostic).
    matched = _match_redirect_uri(client.get("redirectUris") or [], query.get("redirect_uri"))
    if not matched or not query.get("redirect_uri"):
        return handle_redirect(ctx, _get_error_url(ctx, "invalid_redirect", "invalid redirect uri"))

    # 6. Scope validation.
    raw_scope = query.get("scope")
    requested_scopes = [s for s in raw_scope.split(" ") if s] if raw_scope else None
    if requested_scopes is not None:
        valid = set(client.get("scopes") or opts.scopes or [])
        invalid = [s for s in requested_scopes if s not in valid]
        if invalid:
            return handle_redirect(
                ctx,
                format_error_url(
                    query["redirect_uri"],
                    "invalid_scope",
                    f"The following scopes are invalid: {', '.join(invalid)}",
                    query.get("state"),
                    get_issuer(ctx, opts),
                ),
            )
    if requested_scopes is None:
        requested_scopes = client.get("scopes") or opts.scopes or []
        query["scope"] = " ".join(requested_scopes)

    # 7. PKCE enforcement.
    reason = is_pkce_required(client, requested_scopes)
    if reason and not (query.get("code_challenge") and query.get("code_challenge_method")):
        return handle_redirect(
            ctx,
            format_error_url(
                query["redirect_uri"], "invalid_request", reason, query.get("state"),
                get_issuer(ctx, opts),
            ),
        )
    if query.get("code_challenge") or query.get("code_challenge_method"):
        if not (query.get("code_challenge") and query.get("code_challenge_method")):
            return handle_redirect(
                ctx,
                format_error_url(
                    query["redirect_uri"],
                    "invalid_request",
                    "code_challenge and code_challenge_method must both be provided",
                    query.get("state"),
                    get_issuer(ctx, opts),
                ),
            )
        if query["code_challenge_method"] != "S256":
            return handle_redirect(
                ctx,
                format_error_url(
                    query["redirect_uri"],
                    "invalid_request",
                    "invalid code_challenge method, only S256 is supported",
                    query.get("state"),
                    get_issuer(ctx, opts),
                ),
            )

    # 8. Session / prompt gates.
    session = await ctx.get_session()
    if not session or "login" in prompt_set or "create" in prompt_set:
        if prompt_none:
            return _redirect_prompt_none_error(
                ctx, opts, query, "login_required", "authentication required"
            )
        return _redirect_with_prompt_code(
            ctx, opts, query, "create" if "create" in prompt_set else "login"
        )

    ctx_common = {
        "headers": ctx.request.headers,
        "user": session["user"],
        "session": session["session"],
        "scopes": requested_scopes,
    }

    if settings.get("isAuthorize") and "select_account" in prompt_set:
        return _redirect_with_prompt_code(ctx, opts, query, "select_account")
    if (
        settings.get("isAuthorize")
        and select_account
        and await _maybe_await(select_account["shouldRedirect"](ctx_common))
    ):
        if prompt_none:
            return _redirect_prompt_none_error(
                ctx, opts, query, "account_selection_required",
                "End-User account selection is required",
            )
        return _redirect_with_prompt_code(ctx, opts, query, "select_account")

    signup = getattr(opts, "signup", None)
    if signup and signup.get("shouldRedirect"):
        result = await _maybe_await(signup["shouldRedirect"](ctx_common))
        if result:
            if prompt_none:
                return _redirect_prompt_none_error(
                    ctx, opts, query, "interaction_required", "End-User interaction is required"
                )
            return _redirect_with_prompt_code(
                ctx, opts, query, "create", page=result if isinstance(result, str) else None
            )

    post_login = getattr(opts, "post_login", None)
    if (
        not settings.get("postLogin")
        and post_login
        and await _maybe_await(post_login["shouldRedirect"](ctx_common))
    ):
        if prompt_none:
            return _redirect_prompt_none_error(
                ctx, opts, query, "interaction_required", "End-User interaction is required"
            )
        return _redirect_with_prompt_code(ctx, opts, query, "post_login")

    if "consent" in prompt_set:
        return _redirect_with_prompt_code(
            ctx, opts, query, "consent", session_id=session["session"]["id"]
        )

    reference_id = None
    if post_login and post_login.get("consentReferenceId"):
        reference_id = await _maybe_await(
            post_login["consentReferenceId"](
                {"user": session["user"], "session": session["session"], "scopes": requested_scopes}
            )
        )

    auth_time = int(session["session"]["createdAt"].timestamp() * 1000)

    # 9. Consent.
    if client.get("skipConsent"):
        return await redirect_with_authorization_code(
            ctx, opts, query=query, client_id=client["clientId"], user_id=session["user"]["id"],
            session_id=session["session"]["id"], auth_time=auth_time, reference_id=reference_id,
        )

    consent = await _find_consent(ctx, client["clientId"], session["user"]["id"], reference_id)
    if not consent or not all(s in consent.get("scopes", []) for s in requested_scopes):
        if prompt_none:
            return _redirect_prompt_none_error(
                ctx, opts, query, "consent_required", "End-User consent is required"
            )
        return _redirect_with_prompt_code(
            ctx, opts, query, "consent", session_id=session["session"]["id"]
        )

    return await redirect_with_authorization_code(
        ctx, opts, query=query, client_id=client["clientId"], user_id=session["user"]["id"],
        session_id=session["session"]["id"], auth_time=auth_time, reference_id=reference_id,
    )


def _match_redirect_uri(registered_uris: list[str], requested: str | None) -> bool:
    if not requested:
        return False
    req = urlsplit(requested)
    for registered in registered_uris:
        if registered == requested:
            return True
        reg = urlsplit(registered)
        if (
            reg.hostname
            and is_loopback_ip(reg.hostname)
            and reg.hostname == req.hostname
            and reg.path == req.path
            and reg.scheme == req.scheme
            and reg.query == req.query
        ):
            return True
    return False


async def _find_consent(
    ctx: Ctx, client_id: str, user_id: str, reference_id: str | None
) -> dict[str, Any] | None:
    from ...adapters.base import Where

    where = [Where("clientId", client_id), Where("userId", user_id)]
    if reference_id:
        where.append(Where("referenceId", reference_id))
    return await ctx.adapter.find_one("oauthConsent", where)
