"""OIDC logout: RP-Initiated Logout with OP confirmation, and Back-Channel Logout.

Port of TS ``packages/oauth-provider/src/logout.ts`` at v1.7.6 (e0d2b9eb9 back-channel logout,
69acb7a3d effects deferred until the session deletion commits, f451d1c75 complete RP-initiated
flow).

``GET|POST /oauth2/end-session`` merges query and body ``{id_token_hint?, client_id?,
post_logout_redirect_uri?, state?}``. A verified ``id_token_hint`` naming the current browser
session (or a hint sent without browser cookies) ends that session; everything else goes
through a signed, five minute confirmation cookie completed by ``POST
/oauth2/end-session/confirm``. Browser navigations get small HTML pages, other callers get
OAuth JSON errors. A redirect only goes to an exact registered ``post_logout_redirect_uri``.

Every session deletion runs the ``session.delete`` hooks from :func:`session_delete_hooks`:
``before`` captures the session's OAuth token ids and the clients to notify, ``after`` (queued
by the internal adapter until a surrounding transaction commits) revokes those tokens and POSTs
one ``logout+jwt`` Logout Token per client ``backchannelLogoutUri``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

import jwt as pyjwt

from ...adapters.base import Where
from ...crypto import generate_id, sign_value, unsign_value
from ...session import build_cookie, cookie_name, delete_session_cookies, utcnow
from ...types import AuthResponse, Ctx
from .authorize import get_issuer
from .client_crud import get_client
from .utils import (
    OAuthError,
    _decrypt_stored_client_secret,
    _load_verify_keys,
    get_jwt_plugin,
    handle_redirect,
    resolve_ctx_secret_config,
    resolve_subject_identifier,
    safe_url_issue,
)

if TYPE_CHECKING:
    from ...auth import BetterAuth

logger = logging.getLogger("better_auth")

# --- back-channel logout (logout.ts:22-329) -----------------------------------------------

BACKCHANNEL_LOGOUT_EVENT_URI = "http://schemas.openid.net/event/backchannel-logout"
LOGOUT_TOKEN_JWT_TYP = "logout+jwt"
#: Spec section 4 recommends at most two minutes to limit replay.
LOGOUT_TOKEN_LIFETIME_SECONDS = 120
#: One attempt per RP (spec 2.5: the OP SHOULD NOT retransmit) within this ceiling.
BACKCHANNEL_DISPATCH_TIMEOUT_SECONDS = 5.0


async def prepare_backchannel_logout_plan(
    auth: BetterAuth, opts: Any, session_id: str, user_id: str | None
) -> dict[str, Any] | None:
    """Read-only phase run before the session row is deleted (a later hook may still veto),
    TS ``prepareBackchannelLogoutPlan`` (logout.ts:126-212). Token ids are captured now because
    their ``sessionId`` is cleared with the session. Access tokens are always revoked, refresh
    tokens unless ``offline_access`` was granted (spec 2.7). ``None`` when there is nothing to do.
    """
    if not user_id:
        return None
    try:
        where = [Where("sessionId", session_id)]
        access_tokens, refresh_tokens = await asyncio.gather(
            auth.adapter.find_many("oauthAccessToken", where),
            auth.adapter.find_many("oauthRefreshToken", where),
        )
        client_ids = {t["clientId"] for t in [*access_tokens, *refresh_tokens]}
        if not client_ids:
            return None
        clients = await auth.adapter.find_many(
            "oauthClient", [Where("clientId", sorted(client_ids), "in")]
        )
        # Logout Tokens are signed on the jwt plugin's JWKS: no delivery when it is disabled.
        eligible = (
            []
            if getattr(opts, "disable_jwt_plugin", False)
            else [c for c in clients if c.get("backchannelLogoutUri") and not c.get("disabled")]
        )
        targets = []
        for client in eligible:
            try:
                targets.append((client, resolve_subject_identifier(client, opts, user_id)))
            except Exception:
                logger.warning(
                    "back-channel logout: unable to resolve subject for client %s",
                    client["clientId"],
                    exc_info=True,
                )
        return {
            "accessTokenIds": [t["id"] for t in access_tokens if not t.get("revoked")],
            "refreshTokenIds": [
                t["id"]
                for t in refresh_tokens
                if not t.get("revoked") and "offline_access" not in (t.get("scopes") or [])
            ],
            "sessionId": session_id,
            "targets": targets,
        }
    except Exception:
        logger.exception("back-channel logout planning failed")
        return None


async def apply_backchannel_logout_plan(auth: BetterAuth, plan: dict[str, Any]) -> None:
    """Revoke the planned tokens, then deliver Logout Tokens (logout.ts:219-255)."""
    revoked_at = utcnow()
    updates = [
        auth.adapter.update_many(model, [Where("id", ids, "in")], {"revoked": revoked_at})
        for model, ids in (
            ("oauthAccessToken", plan["accessTokenIds"]),
            ("oauthRefreshToken", plan["refreshTokenIds"]),
        )
        if ids
    ]
    for result in await asyncio.gather(*updates, return_exceptions=True):
        if isinstance(result, BaseException):
            logger.error("back-channel logout: token revocation update failed", exc_info=result)
    if plan["targets"]:
        await _deliver_logout_tokens(auth, plan)


async def _deliver_logout_tokens(auth: BetterAuth, plan: dict[str, Any]) -> None:
    """Sign one Logout Token per target and POST it form-encoded (logout.ts:269-327). Every
    per-client failure is logged, none propagates."""
    jwt_plugin = get_jwt_plugin(auth)
    iss = getattr(jwt_plugin, "issuer", None) or f"{auth.base_url}{auth.base_path}"
    iat = math.floor(time.time())

    async def deliver(client: dict[str, Any], sub: str) -> None:
        try:
            # Spec 2.4: iss, aud, iat, exp, jti, events and sub + sid; never a nonce.
            token = await jwt_plugin.sign_jwt(
                payload={
                    "iss": iss,
                    "aud": client["clientId"],
                    "sub": sub,
                    "sid": plan["sessionId"],
                    "iat": iat,
                    "exp": iat + LOGOUT_TOKEN_LIFETIME_SECONDS,
                    "jti": generate_id(32),
                    "events": {BACKCHANNEL_LOGOUT_EVENT_URI: {}},
                },
                header={"typ": LOGOUT_TOKEN_JWT_TYP},
            )
            response = await auth.http.post(
                client["backchannelLogoutUri"],
                data={"logout_token": token},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                timeout=BACKCHANNEL_DISPATCH_TIMEOUT_SECONDS,
                follow_redirects=False,
            )
            # Spec 2.8: the RP MUST return 200; an empty 204 is commonly accepted.
            if response.status_code not in (200, 204):
                logger.warning(
                    "back-channel logout to client %s returned %s",
                    client["clientId"],
                    response.status_code,
                )
        except Exception:
            logger.warning(
                "back-channel logout to client %s failed", client["clientId"], exc_info=True
            )

    await asyncio.gather(*(deliver(client, sub) for client, sub in plan["targets"]))


def session_delete_hooks(opts: Any) -> dict[str, Any]:
    """``databaseHooks.session.delete`` of the plugin (oauth.ts:557-605): ``before`` plans,
    ``after`` applies once the row is gone (after commit inside a transaction).

    ponytail: TS keys pending plans by the endpoint context (a WeakMap) and skips deletions
    made outside one; the port's session hooks get no request context on every path, so plans
    are keyed by session id and every deletion is covered. A plan whose deletion is vetoed or
    rolled back stays until that session is deleted again; add a context key if that matters.
    ponytail: TS hands the after phase to ``runInBackgroundOrAwait``; the port has no
    background handler, so it is awaited inline (bounded by the 5 s per-RP timeout).
    ponytail: the plan reads through ``auth.adapter``. SQL adapters share the transaction's
    connection; the memory adapter's transaction clone stays invisible, so tokens created
    inside the deleting transaction are not revoked there.
    """
    plans: dict[str, dict[str, Any]] = {}

    async def before(session: dict[str, Any], ctx: Any = None) -> None:
        plan = await prepare_backchannel_logout_plan(
            opts.auth, opts, session["id"], session.get("userId")
        )
        if plan is not None:
            plans[session["id"]] = plan

    async def after(session: dict[str, Any], ctx: Any = None) -> None:
        plan = plans.pop(session["id"], None)
        if plan is None:
            return
        try:
            await apply_backchannel_logout_plan(opts.auth, plan)
        except Exception:
            logger.exception("Back-channel logout failed after session deletion")

    return {"session": {"delete": {"before": before, "after": after}}}


# --- RP-Initiated Logout (logout.ts:331-1033) ---------------------------------------------

LOGOUT_CONFIRMATION_TTL_SECONDS = 5 * 60
LOGOUT_CONFIRMATION_COOKIE_SUFFIX = ".oauth_logout_confirmation"
_PAGE_HEADERS = [
    ("cache-control", "no-store"),
    (
        "content-security-policy",
        "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
    ("pragma", "no-cache"),
    ("x-content-type-options", "nosniff"),
]
#: TS core ``NO_STORE_HEADERS``, applied by the endpoints' ``noStore`` metadata.
_NO_STORE_HEADERS = [("Cache-Control", "no-store"), ("Pragma", "no-cache")]
_HTML_ESCAPES = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})
_REQUEST_FIELDS = ("id_token_hint", "client_id", "post_logout_redirect_uri", "state")
_NOT_REGISTERED = "The requested post-logout redirect was not registered."
_INVALID_CONFIRMATION = "The logout confirmation is invalid or expired"
_NO_ACTIVE_SESSION = "No active session is available for logout"
_NO_CLIENT = "The logout client does not exist"
_SIGNATURE_ONLY: Any = {
    "verify_signature": True,
    "verify_exp": False,
    "verify_nbf": False,
    "verify_iat": False,
    "verify_aud": False,
    "verify_iss": False,
    "verify_sub": False,
    "verify_jti": False,
}

Cookies = list[str]
Result = AuthResponse | None


def _escape_html(value: str) -> str:
    return value.translate(_HTML_ESCAPES)


def _is_browser_navigation(ctx: Ctx) -> bool:
    """logout.ts:378-387: not a CORS fetch, and a navigation or an HTML ``Accept``."""
    headers = ctx.request.headers
    mode = headers.get("sec-fetch-mode")
    if mode == "cors":
        return False
    accept = headers.get("accept") or ""
    return mode == "navigate" or "text/html" in accept or "application/xhtml+xml" in accept


def _logout_page(title: str, body: str, status: int = 200) -> AuthResponse:
    html = (
        f'<!doctype html><html><head><meta charset="utf-8"><title>{_escape_html(title)}'
        f"</title></head><body>{body}</body></html>"
    )
    return AuthResponse(
        status=status,
        body=html,
        media_type="text/html; charset=utf-8",
        headers=list(_PAGE_HEADERS),
    )


def _confirmation_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}".removesuffix("/") + (
        "/oauth2/end-session/confirm"
    )


def _confirmation_page(ctx: Ctx) -> AuthResponse:
    action = _escape_html(_confirmation_url(ctx))
    return _logout_page(
        "Confirm logout",
        "<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p>"
        f'<form method="post" data-oidc-logout-confirmation action="{action}"><button '
        'type="submit" name="action" value="confirm">Confirm logout</button></form></main>',
    )


def _success_page(redirect_invalid: bool) -> AuthResponse:
    message = f"Logged out. {_escape_html(_NOT_REGISTERED)}" if redirect_invalid else "Logged out."
    return _logout_page(
        "Logged out", f'<main><p data-oidc-logout-state="logged-out">{message}</p></main>'
    )


def _protocol_error(ctx: Ctx, status: int, error: str, description: str) -> AuthResponse:
    """HTML error page for browser navigations, OAuth JSON otherwise (logout.ts:443-458)."""
    if _is_browser_navigation(ctx):
        return _logout_page(
            "Logout error",
            "<main><h1>Logout error</h1>"
            f'<p data-oidc-logout-state="error">{_escape_html(description)}</p></main>',
            status,
        )
    raise OAuthError(status, error, description)


def _confirmation_cookie(ctx: Ctx, value: str, max_age: int) -> str:
    """The session token cookie's attributes, scoped to the confirm path (logout.ts:464-476)."""
    path = urlsplit(_confirmation_url(ctx)).path or "/oauth2/end-session/confirm"
    base = "session_token" + LOGOUT_CONFIRMATION_COOKIE_SUFFIX
    parts = build_cookie(ctx.auth, value, max_age, base).split("; ")
    return "; ".join(f"Path={path}" if part == "Path=/" else part for part in parts)


def _set_confirmation_state(
    ctx: Ctx, cookies: Cookies, session_id: str | None, confirmation: dict[str, Any]
) -> None:
    state = {
        **({"sessionId": session_id} if session_id else {}),
        **confirmation,
        "expiresAt": int(time.time() * 1000) + LOGOUT_CONFIRMATION_TTL_SECONDS * 1000,
    }
    value = json.dumps(state, separators=(",", ":"), ensure_ascii=False)  # JSON.stringify
    cookies.append(
        _confirmation_cookie(
            ctx, sign_value(ctx.auth.secret, value), LOGOUT_CONFIRMATION_TTL_SECONDS
        )
    )


def _clear_confirmation_state(ctx: Ctx, cookies: Cookies) -> None:
    cookies.append(_confirmation_cookie(ctx, "", 0))


def _get_confirmation_state(ctx: Ctx) -> dict[str, Any] | None:
    """The signed state, or ``None`` when absent, tampered or malformed (logout.ts:495-547)."""
    name = cookie_name(ctx.auth, "session_token" + LOGOUT_CONFIRMATION_COOKIE_SUFFIX)
    raw = ctx.request.cookies().get(name)
    value = unsign_value(ctx.auth.secret, raw) if raw else None
    if value is None:
        return None
    try:
        record = json.loads(value)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None

    def non_empty(key: str) -> bool:
        return key not in record or (isinstance(record[key], str) and record[key] != "")

    expires_at = record.get("expiresAt")
    if not (
        non_empty("sessionId")
        and non_empty("clientId")
        and non_empty("postLogoutRedirectUri")
        and ("state" not in record or isinstance(record["state"], str))
        and ("redirectInvalid" not in record or isinstance(record["redirectInvalid"], bool))
        and not ("postLogoutRedirectUri" in record and "clientId" not in record)
        and isinstance(expires_at, (int, float))
        and not isinstance(expires_at, bool)
        and math.isfinite(expires_at)
    ):
        return None
    keys = ("sessionId", "clientId", "postLogoutRedirectUri", "state", "redirectInvalid")
    return {**{k: record[k] for k in keys if k in record}, "expiresAt": expires_at}


async def _current_browser_session(ctx: Ctx) -> dict[str, Any] | None:
    """The session named by the signed session cookie, bearer tokens ignored (logout.ts:557)."""
    raw = ctx.request.cookies().get(cookie_name(ctx.auth))
    token = unsign_value(ctx.auth.secret, raw) if raw else None
    if not token:
        return None
    try:
        result = await ctx.internal.find_session(token)
    except Exception as exc:
        logger.exception("Failed to read the current logout session")
        raise OAuthError(500, "server_error", "Unable to read the current session") from exc
    return result["session"] if result else None


async def _find_hinted_session(ctx: Ctx, session_id: str) -> dict[str, Any] | None:
    try:
        return await ctx.adapter.find_one("session", [Where("id", session_id)])
    except Exception as exc:
        logger.exception("Failed to read the hinted logout session")
        raise OAuthError(500, "server_error", "Unable to read the hinted session") from exc


async def _delete_logout_session(ctx: Ctx, session: dict[str, Any]) -> None:
    """Through ``delete_session`` so the session delete hooks (back-channel logout) run."""
    token = session.get("token")
    if not isinstance(token, str) or not token:
        raise OAuthError(500, "server_error", "Unable to complete logout")
    try:
        await ctx.internal.delete_session(token)
    except Exception as exc:
        logger.exception("Failed to delete the logout session")
        raise OAuthError(500, "server_error", "Unable to complete logout") from exc


async def _get_logout_client(ctx: Ctx, opts: Any, client_id: str) -> dict[str, Any] | None:
    try:
        return await get_client(ctx, opts, client_id)
    except Exception as exc:
        logger.exception("Failed to resolve the logout client")
        raise OAuthError(500, "server_error", "Unable to resolve the logout client") from exc


def _audiences(value: Any) -> list[str]:
    return [v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str)]


async def _resolve_hint_client(
    ctx: Ctx, opts: Any, hint: str, client_id: str | None
) -> dict[str, Any] | None:
    """``client_id``, else one client from the unverified hint: ``aud`` string, ``azp``, or a
    single-entry ``aud`` list. Never a lookup per audience (logout.ts:654-674)."""
    if client_id:
        return await _get_logout_client(ctx, opts, client_id)
    try:
        decoded = pyjwt.decode(hint, options={"verify_signature": False})
    except Exception:
        return None
    aud, azp = decoded.get("aud"), decoded.get("azp")
    if isinstance(aud, str) and aud:
        candidate = aud
    elif isinstance(azp, str) and azp:
        candidate = azp
    else:
        audiences = _audiences(aud)
        candidate = audiences[0] if len(audiences) == 1 else None
    return await _get_logout_client(ctx, opts, candidate) if candidate else None


async def _verify_logout_hint(
    ctx: Ctx, opts: Any, hint: str, client: dict[str, Any]
) -> dict[str, Any] | None:
    """Signature (jwt plugin keys, or HS256 with the client secret when the plugin is
    disabled), then ``iss``, ``aud``, ``sid`` and ``sub`` (logout.ts:676-729)."""
    try:
        if getattr(opts, "disable_jwt_plugin", False):
            if not client.get("clientSecret"):
                return None
            secret = await _decrypt_stored_client_secret(
                opts.store_client_secret, client["clientSecret"], resolve_ctx_secret_config(ctx)
            )
            payload = pyjwt.decode(hint, secret, algorithms=["HS256"], options=_SIGNATURE_ONLY)
        else:
            jwt_plugin = get_jwt_plugin(ctx.auth)
            kid = pyjwt.get_unverified_header(hint).get("kid")
            key = (await _load_verify_keys(jwt_plugin)).get(kid)
            if key is None:
                key = (await _load_verify_keys(jwt_plugin, refresh=True)).get(kid)
            if key is None:
                return None
            payload = pyjwt.decode(
                hint, key, algorithms=[jwt_plugin._alg()], options=_SIGNATURE_ONLY
            )
    except Exception:
        return None
    if payload.get("iss") != get_issuer(ctx, opts):
        return None
    if client["clientId"] not in _audiences(payload.get("aud")):
        return None
    sid, sub = payload.get("sid"), payload.get("sub")
    if not (isinstance(sid, str) and sid and isinstance(sub, str) and sub):
        return None
    return payload


def _with_state(uri: str, state: str) -> str:
    """WHATWG ``url.searchParams.set("state", state)`` then ``toString()``."""
    parts = urlsplit(uri)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if any(k == "state" for k, _ in pairs):
        first = next(i for i, (k, _) in enumerate(pairs) if k == "state")
        pairs = [
            (k, state if i == first else v)
            for i, (k, v) in enumerate(pairs)
            if k != "state" or i == first
        ]
    else:
        pairs.append(("state", state))
    path = parts.path or ("/" if parts.scheme in ("http", "https") else "")
    query = urlencode(pairs, quote_via=quote_plus)
    return urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))


def _registered_redirect(
    client: dict[str, Any], requested: str | None, state: str | None
) -> tuple[str | None, bool]:
    """``(uri, invalid)``: only an exact registered ``post_logout_redirect_uri`` (logout.ts:731)."""
    if not requested:
        return None, False
    if requested not in (client.get("postLogoutRedirectUris") or []):
        return None, True
    if not state:
        return requested, False
    try:
        return _with_state(requested, state), False
    except ValueError:
        return None, True


def _confirmation_context(client: dict[str, Any], request: dict[str, str]) -> dict[str, Any]:
    """What the confirmation cookie remembers about the redirect (logout.ts:750-766)."""
    uri = request.get("post_logout_redirect_uri")
    if not uri:
        return {}
    _, invalid = _registered_redirect(client, uri, request.get("state"))
    if invalid:
        return {"redirectInvalid": True}
    context = {"clientId": client["clientId"], "postLogoutRedirectUri": uri}
    if "state" in request:
        context["state"] = request["state"]
    return context


async def _confirmed_redirect(
    ctx: Ctx, opts: Any, state: dict[str, Any]
) -> tuple[str | None, bool]:
    """Re-check the remembered redirect against the current registration (logout.ts:768)."""
    if state.get("redirectInvalid"):
        return None, True
    if not state.get("clientId") or not state.get("postLogoutRedirectUri"):
        return None, False
    client = await _get_logout_client(ctx, opts, state["clientId"])
    if not client or client.get("disabled") or not client.get("enableEndSession"):
        return None, True
    return _registered_redirect(client, state["postLogoutRedirectUri"], state.get("state"))


def _confirmation_required(
    ctx: Ctx,
    cookies: Cookies,
    current: dict[str, Any] | None,
    confirmation: dict[str, Any] | None = None,
) -> AuthResponse:
    """logout.ts:788-819."""
    if current is None:
        if _is_browser_navigation(ctx):
            _set_confirmation_state(ctx, cookies, None, confirmation or {})
            return _confirmation_page(ctx)
        return _protocol_error(ctx, 400, "invalid_request", _NO_ACTIVE_SESSION)
    if not _is_browser_navigation(ctx):
        return _protocol_error(
            ctx, 400, "invalid_request", "User confirmation is required to complete logout"
        )
    _set_confirmation_state(ctx, cookies, current["id"], confirmation or {})
    return _confirmation_page(ctx)


def _finish(ctx: Ctx, uri: str | None, invalid: bool) -> Result:
    if uri:
        return handle_redirect(ctx, uri)
    return _success_page(invalid) if _is_browser_navigation(ctx) else None


def _client_gate(ctx: Ctx, client: dict[str, Any]) -> AuthResponse | None:
    if client.get("disabled"):
        return _protocol_error(ctx, 400, "invalid_client", "The logout client is disabled")
    if not client.get("enableEndSession"):
        return _protocol_error(
            ctx, 401, "invalid_client", "The client is not allowed to initiate logout"
        )
    return None


async def _rp_initiated_logout(ctx: Ctx, opts: Any, request: dict[str, str], cookies: Cookies):
    """TS ``rpInitiatedLogoutEndpoint`` (logout.ts:887-1021)."""
    current = await _current_browser_session(ctx)

    if "id_token_hint" not in request:
        confirmation: dict[str, Any] = {}
        if request.get("client_id"):
            client = await _get_logout_client(ctx, opts, request["client_id"])
            if not client:
                return _protocol_error(ctx, 400, "invalid_client", _NO_CLIENT)
            if (gated := _client_gate(ctx, client)) is not None:
                return gated
            confirmation = _confirmation_context(client, request)
        return _confirmation_required(ctx, cookies, current, confirmation)

    hint = request["id_token_hint"]
    client = await _resolve_hint_client(ctx, opts, hint, request.get("client_id"))
    if not client:
        if current is not None and _is_browser_navigation(ctx):
            return _confirmation_required(ctx, cookies, current)
        return _protocol_error(ctx, 400, "invalid_client", _NO_CLIENT)
    if (gated := _client_gate(ctx, client)) is not None:
        return gated

    payload = await _verify_logout_hint(ctx, opts, hint, client)
    if payload is None:
        if current is not None and _is_browser_navigation(ctx):
            confirmation = (
                _confirmation_context(client, request) if request.get("client_id") else {}
            )
            return _confirmation_required(ctx, cookies, current, confirmation)
        return _protocol_error(ctx, 401, "invalid_token", "The id_token_hint is invalid")

    session_id = payload["sid"]
    hinted = await _find_hinted_session(ctx, session_id)
    matches_current = current is not None and current["id"] == session_id
    if current is not None and not matches_current:
        return _confirmation_required(ctx, cookies, current, _confirmation_context(client, request))

    uri, invalid = _registered_redirect(
        client, request.get("post_logout_redirect_uri"), request.get("state")
    )
    to_delete = hinted or (current if matches_current else None)
    if to_delete is not None:
        await _delete_logout_session(ctx, to_delete)
    if matches_current:
        cookies.extend(delete_session_cookies(ctx.auth))
    _clear_confirmation_state(ctx, cookies)
    return _finish(ctx, uri, invalid)


async def _complete_confirmed_logout(ctx: Ctx, opts: Any, cookies: Cookies):
    """TS ``completeConfirmedLogout`` (logout.ts:821-872)."""
    state = _get_confirmation_state(ctx)
    current = await _current_browser_session(ctx)
    if state is None or state["expiresAt"] <= time.time() * 1000:
        return _protocol_error(ctx, 400, "invalid_request", _INVALID_CONFIRMATION)
    uri, invalid = await _confirmed_redirect(ctx, opts, state)
    if current is None:
        _clear_confirmation_state(ctx, cookies)
        if uri:
            return handle_redirect(ctx, uri)
        if _is_browser_navigation(ctx):
            return _success_page(invalid)
        return _protocol_error(ctx, 400, "invalid_request", _NO_ACTIVE_SESSION)
    if state.get("sessionId") and state["sessionId"] != current["id"]:
        return _protocol_error(ctx, 400, "invalid_request", _INVALID_CONFIRMATION)

    await _delete_logout_session(ctx, current)
    cookies.extend(delete_session_cookies(ctx.auth))
    _clear_confirmation_state(ctx, cookies)
    return _finish(ctx, uri, invalid)


# --- endpoints (oauth.ts:1432-1503) -------------------------------------------------------


def _request_body(ctx: Ctx) -> dict[str, Any]:
    """Form or JSON body of a POST; GET carries none.

    ponytail: TS answers other media types with 415 (``allowedMediaTypes``); like the rest of
    this plugin the port reads form, else JSON, without that gate."""
    request = ctx.request
    if request.method != "POST" or not request.body:
        return {}
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype == "application/x-www-form-urlencoded":
        return dict(parse_qsl(request.body.decode("utf-8", "replace"), keep_blank_values=True))
    body = ctx.body()
    return body if isinstance(body, dict) else {}


def _validate_logout_fields(source: dict[str, Any]) -> dict[str, str]:
    """``rpInitiatedLogoutRequestSchema`` (oauth.ts:83-88) with the OAuth issue mapping."""
    fields: dict[str, str] = {}
    for name in _REQUEST_FIELDS:
        if name not in source:
            continue
        if not isinstance(source[name], str):
            raise OAuthError(400, "invalid_request", f"{name} must be a string")
        fields[name] = source[name]
    uri = fields.get("post_logout_redirect_uri")
    if uri is not None and (issue := safe_url_issue(uri)):
        raise OAuthError(400, "invalid_request", f"post_logout_redirect_uri: {issue}")
    return fields


async def _no_store(ctx: Ctx, run: Callable[[Cookies], Awaitable[Any]]) -> AuthResponse:
    """Run a handler with its cookies and the ``noStore`` headers on every outcome."""
    cookies: Cookies = []
    try:
        result = await run(cookies)
    except OAuthError as error:
        response = error.to_response()
    else:
        response = result if isinstance(result, AuthResponse) else AuthResponse(body=result)
    present = {name.lower() for name, _ in response.headers}
    response.headers = [
        *(("set-cookie", cookie) for cookie in cookies),
        *response.headers,
        *((k, v) for k, v in _NO_STORE_HEADERS if k.lower() not in present),
    ]
    return response


async def end_session_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """``GET|POST /oauth2/end-session``: query and body merged, body wins."""
    body = _validate_logout_fields(_request_body(ctx))
    request = {**_validate_logout_fields(dict(ctx.request.query)), **body}
    return await _no_store(ctx, lambda cookies: _rp_initiated_logout(ctx, opts, request, cookies))


async def end_session_confirmation_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """``POST /oauth2/end-session/confirm`` with ``action=confirm``; the signed cookie is the
    only confirmation context it reads."""
    body = _request_body(ctx)
    if "action" not in body:
        raise OAuthError(400, "invalid_request", "action is required")
    if body["action"] != "confirm":
        raise OAuthError(400, "invalid_request", "action must be one of: confirm")
    return await _no_store(ctx, lambda cookies: _complete_confirmed_logout(ctx, opts, cookies))
