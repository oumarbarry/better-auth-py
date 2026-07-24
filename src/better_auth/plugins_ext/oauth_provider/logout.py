"""GET /oauth2/end-session — OIDC RP-Initiated Logout.

Port of TS ``packages/oauth-provider/src/logout.ts`` (v1.6.23). Query ``{id_token_hint (required),
client_id?, post_logout_redirect_uri?, state?}``. The client is resolved from ``client_id`` or the
``id_token_hint`` audience; it must exist, be enabled, and have ``enable_end_session``. The id_token
is signature-verified against the jwt plugin's EdDSA JWKS (the HS256/``disable_jwt_plugin`` path is
rejected at init and not built), then ``iss`` and ``aud`` are checked manually. The session named by
the id_token's ``sid`` is deleted, and — only when ``post_logout_redirect_uri`` exactly matches a
registered ``postLogoutRedirectUris`` entry — the UA is redirected there with ``state`` appended.
"""

from __future__ import annotations

from typing import Any

import jwt as pyjwt

from ...adapters.base import Where
from ...types import Ctx
from .client_crud import get_client
from .utils import (
    OAuthError,
    _load_verify_keys,
    get_jwt_plugin,
    handle_redirect,
    is_safe_url,
)


def _base_url(ctx: Ctx) -> str:
    return f"{ctx.auth.base_url}{ctx.auth.base_path}"


def _issuer(ctx: Ctx) -> str:
    return getattr(get_jwt_plugin(ctx.auth), "issuer", None) or _base_url(ctx)


async def _verify_id_token_signature(ctx: Ctx, token: str) -> dict[str, Any]:
    """Signature-only verification against the jwt plugin's local EdDSA keys (TS
    ``compactVerify`` — claims are checked manually by the caller)."""
    jwt_plugin = get_jwt_plugin(ctx.auth)
    try:
        header = pyjwt.get_unverified_header(token)
    except Exception as exc:
        raise OAuthError(401, "invalid_token", "invalid id token") from exc
    kid = header.get("kid")
    keys = await _load_verify_keys(jwt_plugin)
    public_key = keys.get(kid)
    if public_key is None:
        keys = await _load_verify_keys(jwt_plugin, refresh=True)
        public_key = keys.get(kid)
    if public_key is None:
        raise OAuthError(401, "invalid_token", "unknown signing key")
    return pyjwt.decode(
        token,
        public_key,
        algorithms=["EdDSA"],
        options={"verify_aud": False, "verify_exp": False, "verify_iss": False},
    )


async def rp_initiated_logout_endpoint(ctx: Ctx, opts: Any):
    query = ctx.request.query
    id_token_hint = query.get("id_token_hint")
    client_id = query.get("client_id")
    post_logout_redirect_uri = query.get("post_logout_redirect_uri")
    state = query.get("state")

    # Spec marks id_token_hint recommended; we require it (DoS) — TS ``logout.ts:27``.
    if not id_token_hint:
        raise OAuthError(401, "invalid_token", "invalid id token")

    client_id_resolved = client_id
    if not client_id_resolved:
        try:
            decoded = pyjwt.decode(id_token_hint, options={"verify_signature": False})
        except Exception as exc:
            raise OAuthError(401, "invalid_token", "invalid id token") from exc
        client_id_resolved = decoded.get("aud")
        if isinstance(client_id_resolved, list):
            client_id_resolved = client_id_resolved[0] if client_id_resolved else None
        if not client_id_resolved:
            raise OAuthError(500, "invalid_request", "id token missing audience")

    # Only clients that opted into end-session may drive RP-initiated logout.
    client = await get_client(ctx, opts, client_id_resolved)
    if not client:
        raise OAuthError(400, "invalid_client", "client doesn't exist")
    if client.get("disabled"):
        raise OAuthError(400, "invalid_client", "client is disabled")
    if not client.get("enableEndSession"):
        raise OAuthError(401, "invalid_client", "client unable to logout")

    id_token_payload = await _verify_id_token_signature(ctx, id_token_hint)

    if _issuer(ctx) != id_token_payload.get("iss"):
        raise OAuthError(500, "invalid_request", "invalid issuer")

    aud = id_token_payload.get("aud")
    id_token_audience = [aud] if isinstance(aud, str) else aud
    if not id_token_audience:
        raise OAuthError(500, "invalid_request", "id token missing audience")
    if client_id and client_id not in id_token_audience:
        raise OAuthError(400, "invalid_request", "audience mismatch")

    session_id = id_token_payload.get("sid")
    if not session_id:
        raise OAuthError(500, "invalid_request", "id token missing session")

    try:
        session = await ctx.adapter.find_one("session", [Where("id", session_id)])
        if session and session.get("token"):
            await ctx.internal.delete_session(session["token"])
        elif session:
            await ctx.adapter.delete("session", [Where("id", session["id"])])
    except Exception:
        pass  # session already gone — continue

    # Redirect only to an exact-match registered, scheme-safe post-logout URI.
    if post_logout_redirect_uri:
        registered = client.get("postLogoutRedirectUris") or []
        if post_logout_redirect_uri in registered and is_safe_url(post_logout_redirect_uri):
            from urllib.parse import urlencode

            uri = post_logout_redirect_uri
            if state:
                sep = "&" if "?" in uri else "?"
                uri = f"{uri}{sep}{urlencode({'state': state})}"
            return handle_redirect(ctx, uri)
    return None
